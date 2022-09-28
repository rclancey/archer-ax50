package ax50

import (
	"fmt"
	"net/url"
)

func (client *Client) Login(password string) error {
	var err error
	client.aes, err = GenAESCipher()
	if err != nil {
		return err
	}
	client.passwordKey, err = client.getPasswordKey()
	if err != nil {
		return err
	}
	client.signer, err = client.getSigner(password)
	if err != nil {
		return err
	}
	client.token, err = client.doLogin(password)
	return err
}

func (client *Client) Logout() error {
	if client.token == "" {
		return nil
	}
	_, err := client.doLogout()
	client.token = ""
	if err != nil {
		return err
	}
	return nil
}

func (client *Client) getPasswordKey() (*RSACipher, error) {
	u := client.MakeURL("login", url.Values{"form": []string{"keys"}})
	data := Operation("read")
	type keysResponse struct {
		Password []string `json:"password"`
	}
	body, err := client.request(u, data, nil, false)
	if err != nil {
		return nil, err
	}
	resp, err := ReadResponse[keysResponse](body)
	if err != nil {
		return nil, err
	}
	if len(resp.Password) != 2 {
		return nil, fmt.Errorf("%d password items", len(resp.Password))
	}
	if len(resp.Password[0]) != 256 {
		return nil, fmt.Errorf("bad N (%d != 256)", len(resp.Password[0]))
	}
	if len(resp.Password[1]) != 6 {
		return nil, fmt.Errorf("bad E (%d != 6)", len(resp.Password[1]))
	}
	return ParseRSAKey(resp.Password)
}

func (client *Client) getSigner(password string) (*RSASigner, error) {
	u := client.MakeURL("login", url.Values{"form": []string{"auth"}})
	data := Operation("read")
	type authResponse struct {
		Key []string `json:"key"`
		Seq int      `json:"seq"`
	}
	body, err := client.request(u, data, nil, false)
	if err != nil {
		return nil, err
	}
	resp, err := ReadResponse[authResponse](body)
	if err != nil {
		return nil, err
	}
	if resp == nil || len(resp.Key) != 2 {
		return nil, fmt.Errorf("no keys")
	}
	if len(resp.Key[0]) != 128 {
		return nil, fmt.Errorf("bad N (%d != 128)", len(resp.Key[0]))
	}
	if len(resp.Key[1]) != 6 {
		return nil, fmt.Errorf("bad E (%d != 6)", len(resp.Key[1]))
	}
	return NewRSASigner(password, resp.Key, resp.Seq, client.aes)
}

func (client *Client) doLogin(password string) (string, error) {
	encryptedPassword, err := client.passwordKey.EncryptHex([]byte(password))
	if err != nil {
		return "", err
	}
	u := client.MakeURL("login", url.Values{"form": []string{"login"}})
	type loginRequest struct {
		Operation string `json:"operation"`
		Password  string `json:"password"`
		//Confirm   *bool  `json:"confirm"`
	}
	type loginResponse struct {
		Token           string `json:"stok"`
		AttemptsAllowed int    `json:"attemptsAllowed"`
		FailureCount    int    `json:"failureCount"`
	}
	data := &loginRequest{
		Operation: "login",
		Password: encryptedPassword,
	}
	/*
	if forceLogin {
		t := true
		data.Confirm = &t
	}
	*/
	body, err := client.request(u, data, client.signer, true)
	if err != nil {
		return "", err
	}
	resp, err := ReadResponse[loginResponse](body)
	if err != nil {
		switch err.Error() {
		case "login failed":
			return "", fmt.Errorf("%w. Remaining attempts: %d/%d", err, resp.AttemptsAllowed, resp.AttemptsAllowed + resp.FailureCount)
		case "exceeded max attempts":
			return "", ErrExceededMaxAttempts
		case "user conflict":
			return "", ErrUserConflict
		default:
			return "", fmt.Errorf("%w: %s", ErrLoginError, err)
		}
	}
	return resp.Token, nil
}

func (client *Client) doLogout() (bool, error) {
	if client.token == "" {
		return false, fmt.Errorf("not logged in")
	}
	u := client.MakeURL("admin/system", url.Values{"form": []string{"logout"}})
	data := Operation("write")
	type logoutResp struct {
	}
	body, err := client.request(u, data, client.signer, false)
	if err != nil {
		return false, err
	}
	_, err = ReadResponse[logoutResp](body)
	if err != nil {
		return false, err
	}
	return true, nil
}
