package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/bartvanbenthem/azuretoken/pkg/tokens"
)

type ResourceGroup struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties map[string]string `json:"properties"`
}

type ResourceGroups struct {
	Value []struct {
		ID         string            `json:"id"`
		Name       string            `json:"name"`
		Type       string            `json:"type"`
		Location   string            `json:"location"`
		Tags       map[string]string `json:"tags,omitempty"`
		Properties map[string]string `json:"properties"`
		ManagedBy  string            `json:"managedBy,omitempty"`
	} `json:"value"`
}

// generic function for azure access tokens
func AccessToken(t tokens.TokenRequester) string {
	token, err := t.GetToken()
	if err != nil {
		log.Println(err)
	}
	return token.AccessToken
}

func RequestRMToken() string {
	// get credentials from environment variables
	appid := os.Getenv("AZURE_CLIENT_ID")
	tenantid := os.Getenv("AZURE_TENANT_ID")
	secret := os.Getenv("AZURE_CLIENT_SECRET")

	credentials := tokens.Credentials{
		ApplicationID: appid,
		TenantID:      tenantid,
		ClientSecret:  secret,
	}

	// get azure resource manager api token
	rmclient := tokens.RMClient{
		Access: credentials,
	}

	token := AccessToken(&rmclient)
	return token
}

func (r *ResourceGroup) List(url, subscr, token string) ResourceGroups {
	requrl := fmt.Sprintf(url, subscr)
	req, err := GetRequest(requrl, token)
	if err != nil {
		log.Println(err)
	}

	var val ResourceGroups
	err = json.Unmarshal(req, &val)
	if err != nil {
		log.Println(err)
	}
	return val
}

// GetRequest implements a function that sends a get request to a url
func GetRequest(url string, token string) ([]byte, error) {
	// Create a Bearer string by appending string access token
	var bearer = "Bearer " + token
	// Create a new request using http
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Println(err)
	}

	// add authorization header to the req
	req.Header.Add("Authorization", bearer)
	req.Header.Add("content-type", "application/json")

	// Send req using http Client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
	}

	return body, err

}

func main() {
	// get azure resource manager token
	token := RequestRMToken()
	// new resource group
	var rg ResourceGroup
	urlrg := "https://management.azure.com/subscriptions/%v/resourcegroups?api-version=2019-10-01"
	// list all application gateways in the specified Azure subscription
	list := rg.List(urlrg, os.Getenv("AZURE_SUBSCRIPTION_ID"), token)
	for _, l := range list.Value {
		fmt.Println(l.Name)
	}

}
