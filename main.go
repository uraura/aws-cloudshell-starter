package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
)

func main() {
	profile := "dev" // TODO: use command line flag
	ctx := context.Background()
	cfg := must(config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(profile)))

	creds := must(cfg.Credentials.Retrieve(ctx))

	hc := http.DefaultClient
	hc.Jar = must(cookiejar.New(nil))

	awsLogin(ctx, hc, creds)
	tbcreds := awsCloudShellCredential(ctx, cfg, hc, creds)
	envID := awsCloudShellEnvironment(ctx, hc, tbcreds)
	session := awsCloudShellSession(ctx, hc, tbcreds, envID)

	fmt.Println("session-manager-plugin", "'"+session+"'", cfg.Region, "StartSession", profile)
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
		debug.PrintStack()
		log.Fatal(err)
	}
}

func must[T any](ret T, err error) T {
	if err != nil {
		debug.PrintStack()
		log.Fatal(err)
	}

	return ret
}

func awsLogin(ctx context.Context, hc *http.Client, creds aws.Credentials) {
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
	login := must(hc.Get(loginURL.String()))
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

func awsCloudShellEnvironment(ctx context.Context, hc *http.Client, tbcreds aws.Credentials) string {
	// ???
	req := must(http.NewRequest(http.MethodPost, "https://cloudshell.ap-northeast-1.amazonaws.com/describeEnvironments",
		io.NopCloser(strings.NewReader(""))))
	res := must(hc.Do(must(v4sign(ctx, tbcreds, req))))
	defer res.Body.Close()
	bs := must(io.ReadAll(res.Body))
	log.Printf("describeEnvironments %s\n", bs)

	//fmt.Printf("%+v\n", tbcreds)
	req = must(http.NewRequest(http.MethodPost, "https://cloudshell.ap-northeast-1.amazonaws.com/createEnvironment",
		io.NopCloser(strings.NewReader("{}"))))
	res = must(hc.Do(must(v4sign(ctx, tbcreds, req))))
	defer res.Body.Close()
	bs = must(io.ReadAll(res.Body))
	log.Printf("createEnvironment %s\n", bs)
	envmap := make(map[string]any)
	must0(json.Unmarshal(bs, &envmap))

	envID := envmap["EnvironmentId"].(string)
	status := envmap["Status"].(string)
	for status != "RUNNING" {
		func() {
			time.Sleep(3 * time.Second)
			sync.OnceFunc(func() {
				req = must(http.NewRequest(http.MethodPost, "https://cloudshell.ap-northeast-1.amazonaws.com/startEnvironment",
					io.NopCloser(strings.NewReader(fmt.Sprintf(`{"EnvironmentId":"%s"}`, envID)))))
				res = must(hc.Do(must(v4sign(ctx, tbcreds, req))))
				defer res.Body.Close()
				bs = must(io.ReadAll(res.Body))
				log.Printf("startEnvironment %s\n", bs)
				must0(json.Unmarshal(bs, &envmap))
			})

			req = must(http.NewRequest(http.MethodPost, "https://cloudshell.ap-northeast-1.amazonaws.com/getEnvironmentStatus",
				io.NopCloser(strings.NewReader(fmt.Sprintf(`{"EnvironmentId":"%s"}`, envID)))))
			res = must(hc.Do(must(v4sign(ctx, tbcreds, req))))
			defer res.Body.Close()
			bs = must(io.ReadAll(res.Body))
			log.Printf("getEnvironmentStatus %s\n", bs)
			must0(json.Unmarshal(bs, &envmap))
			status = envmap["Status"].(string)
		}()
	}

	return envID
}

func awsCloudShellSession(ctx context.Context, hc *http.Client, tbcreds aws.Credentials, envID string) string {
	req := must(http.NewRequest(http.MethodPost, "https://cloudshell.ap-northeast-1.amazonaws.com/createSession",
		strings.NewReader(fmt.Sprintf(`{"EnvironmentId":"%s"}`, envID))))
	res := must(hc.Do(must(v4sign(ctx, tbcreds, req))))
	defer res.Body.Close()
	session := must(io.ReadAll(res.Body))
	log.Printf("createSession %s\n", session)

	// 	path: "/oauth?EnvironmentId=" + csEnvironment.data.EnvironmentId + "&codeVerifier=R0r-XINZhRJqEkRk-2EjocwI2aqrhcjO6IlGRPYcIo0&redirectUri=" + encodeURIComponent('https://auth.cloudshell.' + awsregion + '.aws.amazon.com/callback.js?state=1')
	authURL := must(url.Parse("https://auth.cloudshell.ap-northeast-1.aws.amazon.com/oauth"))
	authURL.RawQuery = url.Values{
		"EnvironmentId": []string{envID},
		"codeVerifier":  []string{"R0r-XINZhRJqEkRk-2EjocwI2aqrhcjO6IlGRPYcIo0"},
		"redirectUri":   []string{"https://auth.cloudshell.ap-northeast-1.aws.amazon.com/callback.js?state=1"},
	}.Encode()
	req = must(http.NewRequest(http.MethodGet, authURL.String(), io.NopCloser(strings.NewReader(""))))
	res = must(hc.Do(must(v4sign(ctx, tbcreds, req))))
	defer res.Body.Close()
	bs := must(io.ReadAll(res.Body))
	//log.Printf("oauthEnvironment %s\n", bs)

	startPos := strings.Index(string(bs), `main("`) + len(`main("`)
	endPos := strings.Index(string(bs[startPos:]), `", `)
	oauthcode := string(bs[startPos : startPos+endPos])
	log.Printf("oauthcode %s\n", oauthcode)

	authcookies := hc.Jar.Cookies(must(url.Parse("https://auth.cloudshell.ap-northeast-1.aws.amazon.com/")))
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
	log.Printf("keybase %s\n", keybase)

	req = must(http.NewRequest(http.MethodPost, "https://cloudshell.ap-northeast-1.amazonaws.com/redeemCode",
		io.NopCloser(bytes.NewReader(must(json.Marshal(map[string]string{
			"AuthCode":      oauthcode,
			"CodeVerifier":  "cfd87ed2-16b3-432e-8278-e3afdfc6b235c1a6b90c-33e3-43a6-9801-02d742274b9c",
			"EnvironmentId": envID,
			"KeyBase":       keybase,
			"RedirectUri":   "https://auth.cloudshell.ap-northeast-1.aws.amazon.com/callback.js?state=1",
		}))))))
	res = must(hc.Do(must(v4sign(ctx, tbcreds, req))))
	defer res.Body.Close()
	bs = must(io.ReadAll(res.Body))
	log.Printf("redeemCode %s\n", bs)
	redeemcodemap := make(map[string]string)
	must0(json.Unmarshal(bs, &redeemcodemap))

	req = must(http.NewRequest(http.MethodPost, "https://cloudshell.ap-northeast-1.amazonaws.com/putCredentials",
		io.NopCloser(bytes.NewReader(must(json.Marshal(map[string]string{
			"EnvironmentId": envID,
			"KeyBase":       keybase,
			"RefreshToken":  redeemcodemap["RefreshToken"],
		}))))))
	res = must(hc.Do(must(v4sign(ctx, tbcreds, req))))
	defer res.Body.Close()
	bs = must(io.ReadAll(res.Body))
	log.Printf("putCredentials %s\n", bs)

	return string(session)
}
