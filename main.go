package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime/debug"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"
)

func init() {
	os.Setenv("AWS_SDK_LOAD_CONFIG", "1")
}

type vpcConfig struct {
	VpcID            string   `json:"VpcId"`
	SubnetIDs        []string `json:"SubnetIds"`
	SecurityGroupIDs []string `json:"SecurityGroupIds"`
}

func (v *vpcConfig) IsValid() bool {
	return v.VpcID != "" && len(v.SubnetIDs) > 0 && len(v.SecurityGroupIDs) > 0
}

type awsCloudShellParams struct {
	httpClient     *http.Client
	creds          aws.Credentials
	envID          string
	initScriptPath string
	session        map[string]string
	cfg            aws.Config
	profile        string
}

var logger = slog.Default()

func main() {
	profile := os.Getenv("AWS_PROFILE")

	var isDebug bool
	flag.BoolVar(&isDebug, "debug", false, "debug mode")

	var initScriptPath string
	flag.StringVar(&initScriptPath, "init-script", "", "init script path")

	var vpc vpcConfig
	flag.StringVar(&vpc.VpcID, "vpc-id", "", "VPC ID")
	var subnetIDs, securityGroupIDs string
	flag.StringVar(&subnetIDs, "subnet-ids", "", "Subnet IDs")
	flag.StringVar(&securityGroupIDs, "security-group-ids", "", "Security Group IDs")
	flag.Parse()
	if isDebug {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}
	vpc.SubnetIDs = strings.Split(subnetIDs, ",")
	vpc.SecurityGroupIDs = strings.Split(securityGroupIDs, ",")

	ctx := context.Background()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	cfg := must(config.LoadDefaultConfig(ctx))
	creds := must(cfg.Credentials.Retrieve(ctx))

	//hc := http.DefaultClient
	hc := &http.Client{
		Transport: otelhttp.NewTransport(
			http.DefaultTransport,
			otelhttp.WithSpanNameFormatter(func(operation string, r *http.Request) string {
				if len(operation) > 0 {
					return operation
				}

				return fmt.Sprintf("%s %s", r.Method, r.URL.Path)
			}),
		),
		Jar: must(cookiejar.New(nil)),
	}

	cleanup := must(SetupTraceProvider(10 * time.Second))
	defer cleanup()

	// get login cookie
	awsLogin(ctx, hc, creds)
	// TODO: not needed?
	//tbcreds := awsCloudShellCredential(ctx, cfg, hc, creds)
	//log.Printf("tbcreds %s\n", tbcreds)
	envID := awsCloudShellEnvironment(ctx, hc, creds, vpc)
	defer awsCloudShellEnvironmentCleanup(ctx, hc, cfg, envID)
	session := awsCloudShellSession(ctx, hc, creds, envID)
	defer awsCloudShellSessionCleanup(ctx, hc, cfg, envID, session["SessionId"])

	awsCloudShell(ctx, awsCloudShellParams{
		httpClient:     hc,
		creds:          creds,
		envID:          envID,
		initScriptPath: initScriptPath,
		session:        session,
		cfg:            cfg,
		profile:        profile,
	})
}

func v4sign(ctx context.Context, creds aws.Credentials, req *http.Request) (*http.Request, error) {
	bs := must(io.ReadAll(req.Body))
	req.Body = io.NopCloser(strings.NewReader(string(bs)))

	hash := sha256.Sum256(bs)

	signer := v4.NewSigner()
	must0(signer.SignHTTP(ctx, creds, req,
		hex.EncodeToString(hash[:]),
		"cloudshell", "ap-northeast-1" /* TODO: fix region */, time.Now()))
	// sha256("{}") = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",

	return req, nil
}

func must0(err error) {
	if err != nil {
		logger.Error("error must be nil", slog.Any("err", err), slog.Any("stack", string(debug.Stack())))
		panic(err)
	}
}

func must[T any](ret T, err error) T {
	if err != nil {
		logger.Error("error must be nil", slog.Any("err", err), slog.Any("stack", string(debug.Stack())))
		panic(err)
	}

	if r, ok := any(ret).(*http.Response); ok {
		if r.StatusCode >= 400 {
			logger.Error("response status must be 2xx or 3xx", slog.Int("statusCode", r.StatusCode), slog.Any("body", must(io.ReadAll(r.Body))))
			panic(fmt.Errorf("response status must be 2xx or 3xx: %d", r.StatusCode))
		}
	}

	return ret
}

func awsLogin(ctx context.Context, hc *http.Client, creds aws.Credentials) {
	ctx, span := tracer.Start(ctx, "awsLogin", trace.WithNewRoot())
	defer span.End()

	signintokenURL := must(url.Parse("https://signin.aws.amazon.com/federation"))
	signintokenURL.RawQuery = url.Values{
		"Action":          []string{"getSigninToken"},
		"SessionDuration": []string{"3600"},
		"Session": []string{string(must(json.Marshal(map[string]string{
			"sessionId":    creds.AccessKeyID,
			"sessionKey":   creds.SecretAccessKey,
			"sessionToken": creds.SessionToken,
		})))},
	}.Encode()
	req := must(http.NewRequestWithContext(ctx, http.MethodGet, signintokenURL.String(), io.NopCloser(strings.NewReader(""))))
	signintoken := must(hc.Do(req))
	defer signintoken.Body.Close()
	body := must(io.ReadAll(signintoken.Body))
	signintokenMap := make(map[string]string)
	must0(json.Unmarshal(body, &signintokenMap))

	loginURL := must(url.Parse("https://signin.aws.amazon.com/federation"))
	loginURL.RawQuery = url.Values{
		"Action":      []string{"login"},
		"Destination": []string{"https://console.aws.amazon.com/console/home"},
		"SigninToken": []string{signintokenMap["SigninToken"]},
	}.Encode()
	req = must(http.NewRequestWithContext(ctx, http.MethodGet, loginURL.String(), io.NopCloser(strings.NewReader(""))))
	login := must(hc.Do(req))
	defer login.Body.Close()
	_ = must(io.ReadAll(login.Body))
}

func awsCloudShellCredential(ctx context.Context, cfg aws.Config, hc *http.Client, creds aws.Credentials) aws.Credentials {
	consoleURLstr := ""
	if cfg.Region == "us-east-1" {
		consoleURLstr = "https://console.aws.amazon.com/cloudshell/home"
	} else {
		consoleURLstr = "https://" + cfg.Region + ".console.aws.amazon.com/cloudshell/home"
	}
	consoleURL := must(url.Parse(consoleURLstr))
	consoleURL.RawQuery = url.Values{
		"region":   []string{cfg.Region},
		"state":    []string{"hashArgs%23"},
		"hashArgs": []string{"%23"},
	}.Encode()
	console := must(hc.Get(consoleURL.String()))
	defer console.Body.Close()
	body := must(io.ReadAll(console.Body))

	startPos := strings.Index(string(body), `<meta name="tb-data" content="`)
	endPos := strings.Index(string(body[startPos:]), `">`)
	tbData := string(body[startPos : startPos+endPos+2])
	tbDataContentPos := strings.Index(tbData, `content="`) + len(`content="`)
	tbDataContent := strings.ReplaceAll(tbData[tbDataContentPos:len(tbData)-2], "&quot;", `"`)
	tbDataMap := make(map[string]any)
	must0(json.Unmarshal([]byte(tbDataContent), &tbDataMap))

	credsURLstr := ""
	if cfg.Region == "us-east-1" {
		credsURLstr = "https://console.aws.amazon.com/cloudshell/tb/creds"
	} else {
		credsURLstr = "https://" + cfg.Region + ".console.aws.amazon.com/cloudshell/tb/creds"
	}
	credsURL := must(url.Parse(credsURLstr))
	req := must(http.NewRequest(http.MethodPost, credsURL.String(), nil))
	req.Header.Set("x-csrf-token", tbDataMap["csrfToken"].(string))
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Referer", consoleURL.String())
	tbcredsresp := must(hc.Do(req))
	defer tbcredsresp.Body.Close()

	body = must(io.ReadAll(tbcredsresp.Body))
	tbcredsmap := make(map[string]string)
	must0(json.Unmarshal(body, &tbcredsmap))

	return aws.Credentials{
		AccessKeyID:     tbcredsmap["accessKeyId"],
		SecretAccessKey: tbcredsmap["secretAccessKey"],
		SessionToken:    tbcredsmap["sessionToken"],
		Expires:         must(time.Parse(time.RFC3339, tbcredsmap["expiration"])),
	}
}

func awsCloudShellEnvironmentCleanup(ctx context.Context, hc *http.Client, cfg aws.Config, envID string) {
	slog.InfoContext(ctx, "cleanup environment", slog.String("envID", envID))
	creds := must(cfg.Credentials.Retrieve(ctx))
	req := must(http.NewRequest(http.MethodPost, "https://cloudshell.ap-northeast-1.amazonaws.com/deleteEnvironment",
		io.NopCloser(strings.NewReader(fmt.Sprintf(`{"EnvironmentId":"%s"}`, envID)))))
	res := must(hc.Do(must(v4sign(ctx, creds, req))))
	defer res.Body.Close()
	//bs := must(io.ReadAll(res.Body))
	//log.Printf("deleteEnvironment %s\n", bs)
}

func awsCloudShellSessionCleanup(ctx context.Context, hc *http.Client, cfg aws.Config, envID, sessionID string) {
	slog.InfoContext(ctx, "cleanup session", slog.String("sessionID", sessionID))
	creds := must(cfg.Credentials.Retrieve(ctx))
	req := must(http.NewRequest(http.MethodPost, "https://cloudshell.ap-northeast-1.amazonaws.com/deleteSession",
		io.NopCloser(strings.NewReader(fmt.Sprintf(`{"EnvironmentId":"%s", "SessionId":"%s"}`, envID, sessionID)))))
	res := must(hc.Do(must(v4sign(ctx, creds, req))))
	defer res.Body.Close()
}

func awsCloudShellEnvironment(ctx context.Context, hc *http.Client, tbcreds aws.Credentials, vpc vpcConfig) string {
	ctx, span := tracer.Start(ctx, "awsCloudShellEnvironment", trace.WithNewRoot())
	defer span.End()

	// ???
	req := must(http.NewRequestWithContext(ctx, http.MethodPost, "https://cloudshell.ap-northeast-1.amazonaws.com/describeEnvironments",
		io.NopCloser(strings.NewReader(""))))
	res := must(hc.Do(must(v4sign(ctx, tbcreds, req))))
	defer res.Body.Close()
	bs := must(io.ReadAll(res.Body))

	//fmt.Printf("%+v\n", tbcreds)
	body := "{}"
	if vpc.IsValid() {
		slog.DebugContext(ctx, "use vpc config", slog.Any("vpc", vpc))
		slog.InfoContext(ctx, "creating vpc-environment takes a few minutes")
		body = string(must(json.Marshal(map[string]any{"VpcConfig": vpc, "EnvironmentName": "env-" + fmt.Sprint(time.Now().Unix())})))
	}
	req = must(http.NewRequestWithContext(ctx, http.MethodPost, "https://cloudshell.ap-northeast-1.amazonaws.com/createEnvironment", io.NopCloser(strings.NewReader(body))))
	res = must(hc.Do(must(v4sign(ctx, tbcreds, req))))
	defer res.Body.Close()
	bs = must(io.ReadAll(res.Body))
	slog.DebugContext(ctx, "createEnvironment", slog.String("body", string(bs)))
	envmap := make(map[string]any)
	must0(json.Unmarshal(bs, &envmap))

	envID := envmap["EnvironmentId"].(string)
	status := envmap["Status"].(string)
	for status != "RUNNING" {
		func() {
			//sync.OnceFunc(func() {
			//	req = must(http.NewRequestWithContext(ctx, http.MethodPost, "https://cloudshell.ap-northeast-1.amazonaws.com/startEnvironment",
			//		io.NopCloser(strings.NewReader(fmt.Sprintf(`{"EnvironmentId":"%s"}`, envID)))))
			//	res = must(hc.Do(must(v4sign(ctx, tbcreds, req))))
			//	defer res.Body.Close()
			//	bs = must(io.ReadAll(res.Body))
			//	slog.DebugContext(ctx, "startEnvironment", slog.String("body", string(bs)))
			//	must0(json.Unmarshal(bs, &envmap))
			//})()
			must0(makeSpan(ctx, "waiter", func() error {
				time.Sleep(3 * time.Second)
				return nil
			}))

			req = must(http.NewRequestWithContext(ctx, http.MethodPost, "https://cloudshell.ap-northeast-1.amazonaws.com/getEnvironmentStatus",
				io.NopCloser(strings.NewReader(fmt.Sprintf(`{"EnvironmentId":"%s"}`, envID)))))
			res = must(hc.Do(must(v4sign(ctx, tbcreds, req))))
			defer res.Body.Close()
			bs = must(io.ReadAll(res.Body))
			slog.DebugContext(ctx, "getEnvironmentStatus", slog.String("body", string(bs)))
			must0(json.Unmarshal(bs, &envmap))
			status = envmap["Status"].(string)
		}()
	}

	return envID
}

func awsCloudShellSession(ctx context.Context, hc *http.Client, tbcreds aws.Credentials, envID string) map[string]string {
	req := must(http.NewRequest(http.MethodPost, "https://cloudshell.ap-northeast-1.amazonaws.com/createSession",
		strings.NewReader(fmt.Sprintf(`{"EnvironmentId":"%s"}`, envID))))
	res := must(hc.Do(must(v4sign(ctx, tbcreds, req))))
	defer res.Body.Close()
	session := must(io.ReadAll(res.Body))
	slog.DebugContext(ctx, "createSession", slog.String("session", string(session)))

	var ret map[string]string
	must0(json.Unmarshal(session, &ret))
	return ret
}

func awsCloudShellInit(ctx context.Context, hc *http.Client, creds aws.Credentials, envID string, initFilePath string) map[string]any {
	req := must(http.NewRequestWithContext(ctx, http.MethodPost, "https://cloudshell.ap-northeast-1.amazonaws.com/getFileUploadUrls",
		io.NopCloser(bytes.NewReader(must(json.Marshal(map[string]string{
			"EnvironmentId":  envID,
			"FileUploadPath": initFilePath,
		}))))))
	res := must(hc.Do(must(v4sign(ctx, creds, req))))
	defer res.Body.Close()
	bs := must(io.ReadAll(res.Body))
	uploadInfoMap := make(map[string]any)
	must0(json.Unmarshal(bs, &uploadInfoMap))
	//log.Printf("getFileUploadUrls %s\n", uploadInfoMap)

	// upload
	fieldname := "file"
	filename := initFilePath
	file := must(os.Open(filename))
	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	for k, v := range uploadInfoMap["FileUploadPresignedFields"].(map[string]any) {
		//log.Printf("%s %s\n", k, v.(string))
		must0(mw.WriteField(k, v.(string)))
	}
	fw := must(mw.CreateFormFile(fieldname, filename))
	must(io.Copy(fw, file))
	contentType := mw.FormDataContentType()
	must0(mw.Close())
	req = must(http.NewRequestWithContext(ctx, http.MethodPost, uploadInfoMap["FileUploadPresignedUrl"].(string), body))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Content-Length", fmt.Sprint(body.Len()))
	//dr := must(httputil.DumpRequest(req, true))
	//log.Printf("dump %v\n", string(dr))
	res = must(hc.Do(req))
	defer res.Body.Close()
	bs = must(io.ReadAll(res.Body))
	//log.Printf("init command:")
	//return fmt.Sprintf(`curl -s -H 'x-amz-server-side-encryption-customer-key: %v' '%v' | bash`, uploadInfoMap["FileDownloadPresignedKey"], uploadInfoMap["FileDownloadPresignedUrl"])
	return uploadInfoMap
}

func heartbeat(ctx context.Context, params awsCloudShellParams) {
	ctx, span := tracer.Start(ctx, "heartbeat", trace.WithNewRoot())
	defer span.End()

	// renew creds
	creds := must(params.cfg.Credentials.Retrieve(ctx))
	//log.Printf("retrieved credentials: access_key_id=%v expiration=%v", creds.AccessKeyID, creds.Expires)
	req := must(http.NewRequestWithContext(ctx, http.MethodPost, "https://cloudshell.ap-northeast-1.amazonaws.com/sendHeartBeat",
		io.NopCloser(strings.NewReader(fmt.Sprintf(`{"EnvironmentId":"%s"}`, params.envID)))))
	res := must(params.httpClient.Do(must(v4sign(ctx, creds, req))))
	defer res.Body.Close()

	authURL := must(url.Parse("https://auth.cloudshell.ap-northeast-1.aws.amazon.com/oauth"))
	authURL.RawQuery = url.Values{
		"EnvironmentId": []string{params.envID},
		"codeVerifier":  []string{"R0r-XINZhRJqEkRk-2EjocwI2aqrhcjO6IlGRPYcIo0"},
		"redirectUri":   []string{"https://auth.cloudshell.ap-northeast-1.aws.amazon.com/callback.js?state=1"},
	}.Encode()
	req = must(http.NewRequestWithContext(ctx, http.MethodGet, authURL.String(), io.NopCloser(strings.NewReader(""))))
	res = must(params.httpClient.Do(must(v4sign(ctx, creds, req))))
	defer res.Body.Close()
	bs := must(io.ReadAll(res.Body))
	//log.Printf("oauthEnvironment %s\n", bs)

	startPos := strings.Index(string(bs), `main("`) + len(`main("`)
	endPos := strings.Index(string(bs[startPos:]), `", `)
	oauthcode := string(bs[startPos : startPos+endPos])
	//log.Printf("oauthcode %s\n", oauthcode)

	authcookies := params.httpClient.Jar.Cookies(must(url.Parse("https://auth.cloudshell.ap-northeast-1.aws.amazon.com/")))
	keybase := ""
	for _, c := range authcookies {
		//log.Printf("authcookie %s\n", c)
		if c.Name != "aws-userInfo" {
			continue
		}
		var userInfo map[string]any
		must0(json.Unmarshal([]byte(must(url.QueryUnescape(c.Value))), &userInfo))
		keybase = userInfo["keybase"].(string)
	}
	//log.Printf("keybase %s\n", keybase)

	req = must(http.NewRequestWithContext(ctx, http.MethodPost, "https://cloudshell.ap-northeast-1.amazonaws.com/redeemCode",
		io.NopCloser(bytes.NewReader(must(json.Marshal(map[string]string{
			"AuthCode":      oauthcode,
			"CodeVerifier":  "cfd87ed2-16b3-432e-8278-e3afdfc6b235c1a6b90c-33e3-43a6-9801-02d742274b9c",
			"EnvironmentId": params.envID,
			"KeyBase":       keybase,
			"RedirectUri":   "https://auth.cloudshell.ap-northeast-1.aws.amazon.com/callback.js?state=1",
		}))))))
	res = must(params.httpClient.Do(must(v4sign(ctx, creds, req))))
	defer res.Body.Close()
	bs = must(io.ReadAll(res.Body))
	//log.Printf("redeemCode %s\n", bs)
	redeemcodemap := make(map[string]string)
	must0(json.Unmarshal(bs, &redeemcodemap))

	req = must(http.NewRequestWithContext(ctx, http.MethodPost, "https://cloudshell.ap-northeast-1.amazonaws.com/putCredentials",
		io.NopCloser(bytes.NewReader(must(json.Marshal(map[string]string{
			"EnvironmentId": params.envID,
			"KeyBase":       keybase,
			"RefreshToken":  redeemcodemap["RefreshToken"],
		}))))))
	res = must(params.httpClient.Do(must(v4sign(ctx, creds, req))))
	defer res.Body.Close()
	bs = must(io.ReadAll(res.Body))
}

func awsCloudShell(ctx context.Context, params awsCloudShellParams) {
	go func(ctx context.Context) {
		logger.DebugContext(ctx, "start sending heartbeat")
		heartbeat(ctx, params)
		ticker := time.NewTicker(45 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case _ = <-ticker.C:
				//log.Printf("send heartbeat at %v", c)
				heartbeat(ctx, params)
			}
		}
	}(ctx)

	initMap := make(map[string]any)
	if params.initScriptPath != "" {
		initMap = awsCloudShellInit(ctx, params.httpClient, params.creds, params.envID, params.initScriptPath)
	}

	// https://github.com/aws/session-manager-plugin/blob/b2b0bcd769d1c0693f77047360748ed45b09a72b/src/sessionmanagerplugin/session/session.go#L121-L130
	cmdctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(cmdctx, "session-manager-plugin", string(must(json.Marshal(params.session))), params.cfg.Region, "StartSession", params.profile)
	defer cancel()

	initcmd := "echo Hello CloudShell!\n"
	if len(initMap) > 0 {
		initcmd = fmt.Sprintf("source <(curl -sSL -H 'x-amz-server-side-encryption-customer-key: %v' '%v')\n", initMap["FileDownloadPresignedKey"], initMap["FileDownloadPresignedUrl"])
	}

	in := io.MultiReader(
		strings.NewReader(initcmd),
		os.Stdin,
	)
	cmd.Stdin = in
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// disable local echo
	//oldState := must(term.MakeRaw(int(os.Stdin.Fd())))
	//defer term.Restore(int(os.Stdin.Fd()), oldState)

	//cmd.Run()
	<-ctx.Done()
	//term.Restore(int(os.Stdin.Fd()), oldState)
	//println()
}
