package ax50

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"

	"golang.org/x/net/publicsuffix"
)

type Client struct {
	host string
	token string
	aes *AESCipher
	passwordKey *RSACipher
	signer *RSASigner
	client *http.Client
}

func NewClient(host string) (*Client, error) {
	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return nil, err
	}
	return &Client{
		host: host,
		client: &http.Client{Jar: jar},
	}, nil
}

func (client *Client) MakeURL(endpoint string, query url.Values) *url.URL {
	u := &url.URL{
		Scheme: "http",
		Host: client.host,
		Path: fmt.Sprintf("/cgi-bin/luci/;stok=%s/%s", client.token, endpoint),
	}
	if query != nil {
		u.RawQuery = query.Encode()
	}
	return u
}

func (client *Client) MakeFormURL(endpoint, form string) *url.URL {
	return client.MakeURL(endpoint, url.Values{"form": []string{form}})
}

func Operation(op string) map[string]string {
	return map[string]string{"operation": op}
}

type ClientList struct {
	Wireless []*AccessDevice `json:"access_devices_wireless_host"`
	Wired    []*AccessDevice `json:"access_devices_wired"`
}

type AccessDevice struct {
	Hostname string `json:"hostname"`
	IPv4     string `json:"ipaddr"`
	MAC      string `json:"macaddr"`
	WireType string `json:"wire_type"`
}

func (client *Client) GetClientList() (*ClientList, error) {
	u := client.MakeFormURL("admin/status", "client_status")
	data := Operation("read")
	body, err := client.request(u, data, client.signer, false)
	if err != nil {
		return nil, err
	}
	return ReadResponse[ClientList](body)
}

func (client *Client) request(u *url.URL, data interface{}, signer *RSASigner, isLogin bool) ([]byte, error) {
	var err error
	if signer != nil {
		data, err = signer.Sign(data, isLogin)
		if err != nil {
			return nil, err
		}
	}
	payload, err := MarshalForm(data)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	res, err := client.client.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		if err != nil {
			return body, fmt.Errorf("%s (%w)", res.Status, err)
		}
		return body, errors.New(res.Status)
	} else if err != nil {
		return body, err
	}
	if signer != nil {
		body, err = signer.DecryptResponse(body)
		if err != nil {
			return nil, err
		}
	}
	return body, nil
}
