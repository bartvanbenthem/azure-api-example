package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/bartvanbenthem/azuretoken"
)

func main() {
	// load environment variables for Azure graph token request
	applicationid := os.Getenv("AZURE_CLIENT_ID")
	tenantid := os.Getenv("AZURE_TENANT_ID")
	secret := os.Getenv("AZURE_CLIENT_SECRET")
	turl := os.Getenv("AZURE_TOKEN_URL")
	resource := os.Getenv("AZURE_RESURL")
	subscr := os.Getenv("AZURE_SUBSCRIPTION_ID")

	// get azure graph token
	var token azuretoken.Token
	tokenurl := fmt.Sprintf(turl, tenantid)
	requestBody := strings.NewReader(fmt.Sprintf("grant_type=client_credentials&client_id=%v&client_secret=%v&resource=%v", applicationid, secret, resource))
	t := token.GetToken(requestBody, tokenurl)

	urlrg := "https://management.azure.com/subscriptions/%v/resourcegroups?api-version=2019-10-01"
	urlag := "https://management.azure.com/subscriptions/%v/resourceGroups/%v/providers/Microsoft.Network/applicationGateways?api-version=2020-04-01"

	var rg ResourceGroup
	var ag ApplicationGateway

	// list all application gateways in the specified Azure subscription
	list := rg.List(urlrg, subscr, t)
	for _, l := range list.Value {
		ag := ag.List(urlag, subscr, l.Name, t)
		for _, a := range ag.Value {
			fmt.Println(a.Name)
		}
	}

}

func (a ApplicationGateway) List(url, subscr, rg, token string) ApplicationGateways {
	requrl := fmt.Sprintf(url, subscr, rg)
	req, err := GetRequest(requrl, token)
	if err != nil {
		log.Println(err)
	}

	var val ApplicationGateways
	err = json.Unmarshal(req, &val)
	if err != nil {
		log.Println(err)
	}

	return val
}

func (r ResourceGroup) List(url, subscr, token string) ResourceGroups {
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

// AZURE RESOURCE STRUCTS

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

type ApplicationGateway struct {
	Name       string `json:"name"`
	ID         string `json:"id"`
	Etag       string `json:"etag"`
	Type       string `json:"type"`
	APIVersion string `json:"apiVersion"`
	Location   string `json:"location"`
	Tags       struct {
	} `json:"tags"`
	Properties struct {
		Sku struct {
			Name     string `json:"name"`
			Tier     string `json:"tier"`
			Capacity int    `json:"capacity"`
		} `json:"sku"`
		SslPolicy struct {
			DisabledSslProtocols []string `json:"disabledSslProtocols"`
			PolicyType           string   `json:"policyType"`
			PolicyName           string   `json:"policyName"`
			CipherSuites         []string `json:"cipherSuites"`
			MinProtocolVersion   string   `json:"minProtocolVersion"`
		} `json:"sslPolicy"`
		GatewayIPConfigurations []struct {
			ID         string `json:"id"`
			Properties struct {
				Subnet struct {
					ID string `json:"id"`
				} `json:"subnet"`
			} `json:"properties"`
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"gatewayIPConfigurations"`
		AuthenticationCertificates []struct {
			ID         string `json:"id"`
			Properties struct {
				Data string `json:"data"`
			} `json:"properties"`
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"authenticationCertificates"`
		TrustedRootCertificates []struct {
			ID         string `json:"id"`
			Properties struct {
				Data             string `json:"data"`
				KeyVaultSecretID string `json:"keyVaultSecretId"`
			} `json:"properties"`
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"trustedRootCertificates"`
		SslCertificates []struct {
			ID         string `json:"id"`
			Properties struct {
				Data             string `json:"data"`
				Password         string `json:"password"`
				PublicCertData   string `json:"publicCertData"`
				KeyVaultSecretID string `json:"keyVaultSecretId"`
			} `json:"properties"`
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"sslCertificates"`
		FrontendIPConfigurations []struct {
			ID         string `json:"id"`
			Properties struct {
				PrivateIPAddress          string `json:"privateIPAddress"`
				PrivateIPAllocationMethod string `json:"privateIPAllocationMethod"`
				Subnet                    struct {
					ID string `json:"id"`
				} `json:"subnet"`
				PublicIPAddress struct {
					ID string `json:"id"`
				} `json:"publicIPAddress"`
			} `json:"properties"`
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"frontendIPConfigurations"`
		FrontendPorts []struct {
			ID         string `json:"id"`
			Properties struct {
				Port int `json:"port"`
			} `json:"properties"`
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"frontendPorts"`
		Probes []struct {
			ID         string `json:"id"`
			Properties struct {
				Protocol                            string `json:"protocol"`
				Host                                string `json:"host"`
				Path                                string `json:"path"`
				Interval                            int    `json:"interval"`
				Timeout                             int    `json:"timeout"`
				UnhealthyThreshold                  int    `json:"unhealthyThreshold"`
				PickHostNameFromBackendHTTPSettings bool   `json:"pickHostNameFromBackendHttpSettings"`
				MinServers                          int    `json:"minServers"`
				Match                               struct {
					Body        string   `json:"body"`
					StatusCodes []string `json:"statusCodes"`
				} `json:"match"`
			} `json:"properties"`
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"probes"`
		BackendAddressPools []struct {
			ID         string `json:"id"`
			Properties struct {
				BackendIPConfigurations []struct {
					ID         string `json:"id"`
					Properties struct {
						VirtualNetworkTaps []struct {
							ID       string `json:"id"`
							Location string `json:"location"`
							Tags     struct {
							} `json:"tags"`
							Properties struct {
								DestinationNetworkInterfaceIPConfiguration     string `json:"destinationNetworkInterfaceIPConfiguration"`
								DestinationLoadBalancerFrontEndIPConfiguration struct {
									ID         string `json:"id"`
									Properties struct {
										PrivateIPAddress          string `json:"privateIPAddress"`
										PrivateIPAllocationMethod string `json:"privateIPAllocationMethod"`
										Subnet                    struct {
											ID         string `json:"id"`
											Properties struct {
												AddressPrefix        string   `json:"addressPrefix"`
												AddressPrefixes      []string `json:"addressPrefixes"`
												NetworkSecurityGroup struct {
													ID       string `json:"id"`
													Location string `json:"location"`
													Tags     struct {
													} `json:"tags"`
													Properties struct {
														SecurityRules []struct {
															ID         string `json:"id"`
															Properties struct {
																Description                     string   `json:"description"`
																Protocol                        string   `json:"protocol"`
																SourcePortRange                 string   `json:"sourcePortRange"`
																DestinationPortRange            string   `json:"destinationPortRange"`
																SourceAddressPrefix             string   `json:"sourceAddressPrefix"`
																SourceAddressPrefixes           []string `json:"sourceAddressPrefixes"`
																SourceApplicationSecurityGroups []struct {
																	ID       string `json:"id"`
																	Location string `json:"location"`
																	Tags     struct {
																	} `json:"tags"`
																	Properties struct {
																	} `json:"properties"`
																} `json:"sourceApplicationSecurityGroups"`
																DestinationAddressPrefix             string   `json:"destinationAddressPrefix"`
																DestinationAddressPrefixes           []string `json:"destinationAddressPrefixes"`
																DestinationApplicationSecurityGroups []struct {
																	ID       string `json:"id"`
																	Location string `json:"location"`
																	Tags     struct {
																	} `json:"tags"`
																	Properties struct {
																	} `json:"properties"`
																} `json:"destinationApplicationSecurityGroups"`
																SourcePortRanges      []string `json:"sourcePortRanges"`
																DestinationPortRanges []string `json:"destinationPortRanges"`
																Access                string   `json:"access"`
																Priority              string   `json:"priority"`
																Direction             string   `json:"direction"`
															} `json:"properties"`
															Name string `json:"name"`
														} `json:"securityRules"`
														DefaultSecurityRules []struct {
															ID         string `json:"id"`
															Properties struct {
																Description                     string   `json:"description"`
																Protocol                        string   `json:"protocol"`
																SourcePortRange                 string   `json:"sourcePortRange"`
																DestinationPortRange            string   `json:"destinationPortRange"`
																SourceAddressPrefix             string   `json:"sourceAddressPrefix"`
																SourceAddressPrefixes           []string `json:"sourceAddressPrefixes"`
																SourceApplicationSecurityGroups []struct {
																	ID       string `json:"id"`
																	Location string `json:"location"`
																	Tags     struct {
																	} `json:"tags"`
																	Properties struct {
																	} `json:"properties"`
																} `json:"sourceApplicationSecurityGroups"`
																DestinationAddressPrefix             string   `json:"destinationAddressPrefix"`
																DestinationAddressPrefixes           []string `json:"destinationAddressPrefixes"`
																DestinationApplicationSecurityGroups []struct {
																	ID       string `json:"id"`
																	Location string `json:"location"`
																	Tags     struct {
																	} `json:"tags"`
																	Properties struct {
																	} `json:"properties"`
																} `json:"destinationApplicationSecurityGroups"`
																SourcePortRanges      []string `json:"sourcePortRanges"`
																DestinationPortRanges []string `json:"destinationPortRanges"`
																Access                string   `json:"access"`
																Priority              string   `json:"priority"`
																Direction             string   `json:"direction"`
															} `json:"properties"`
															Name string `json:"name"`
														} `json:"defaultSecurityRules"`
														ResourceGUID string `json:"resourceGuid"`
													} `json:"properties"`
												} `json:"networkSecurityGroup"`
												RouteTable struct {
													ID       string `json:"id"`
													Location string `json:"location"`
													Tags     struct {
													} `json:"tags"`
													Properties struct {
														Routes []struct {
															ID         string `json:"id"`
															Properties struct {
																AddressPrefix    string `json:"addressPrefix"`
																NextHopType      string `json:"nextHopType"`
																NextHopIPAddress string `json:"nextHopIpAddress"`
															} `json:"properties"`
															Name string `json:"name"`
														} `json:"routes"`
														DisableBgpRoutePropagation string `json:"disableBgpRoutePropagation"`
													} `json:"properties"`
												} `json:"routeTable"`
												NatGateway struct {
													ID string `json:"id"`
												} `json:"natGateway"`
												ServiceEndpoints []struct {
													Service   string   `json:"service"`
													Locations []string `json:"locations"`
												} `json:"serviceEndpoints"`
												ServiceEndpointPolicies []struct {
													ID       string `json:"id"`
													Location string `json:"location"`
													Tags     struct {
													} `json:"tags"`
													Properties struct {
														ServiceEndpointPolicyDefinitions []struct {
															ID         string `json:"id"`
															Properties struct {
																Description      string   `json:"description"`
																Service          string   `json:"service"`
																ServiceResources []string `json:"serviceResources"`
															} `json:"properties"`
															Name string `json:"name"`
														} `json:"serviceEndpointPolicyDefinitions"`
													} `json:"properties"`
												} `json:"serviceEndpointPolicies"`
												ResourceNavigationLinks []struct {
													ID         string `json:"id"`
													Properties struct {
														LinkedResourceType string `json:"linkedResourceType"`
														Link               string `json:"link"`
													} `json:"properties"`
													Name string `json:"name"`
												} `json:"resourceNavigationLinks"`
												ServiceAssociationLinks []struct {
													ID         string `json:"id"`
													Properties struct {
														LinkedResourceType string `json:"linkedResourceType"`
														Link               string `json:"link"`
													} `json:"properties"`
													Name string `json:"name"`
												} `json:"serviceAssociationLinks"`
												Delegations []struct {
													ID         string `json:"id"`
													Properties struct {
														ServiceName string   `json:"serviceName"`
														Actions     []string `json:"actions"`
													} `json:"properties"`
													Name string `json:"name"`
												} `json:"delegations"`
											} `json:"properties"`
											Name string `json:"name"`
										} `json:"subnet"`
										PublicIPAddress struct {
											ID       string `json:"id"`
											Location string `json:"location"`
											Tags     struct {
											} `json:"tags"`
											Sku struct {
												Name string `json:"name"`
											} `json:"sku"`
											Properties struct {
												PublicIPAllocationMethod string `json:"publicIPAllocationMethod"`
												PublicIPAddressVersion   string `json:"publicIPAddressVersion"`
												DNSSettings              struct {
													DomainNameLabel string `json:"domainNameLabel"`
													Fqdn            string `json:"fqdn"`
													ReverseFqdn     string `json:"reverseFqdn"`
												} `json:"dnsSettings"`
												DdosSettings struct {
													DdosCustomPolicy struct {
														ID string `json:"id"`
													} `json:"ddosCustomPolicy"`
													ProtectionCoverage string `json:"protectionCoverage"`
												} `json:"ddosSettings"`
												IPTags []struct {
													IPTagType string `json:"ipTagType"`
													Tag       string `json:"tag"`
												} `json:"ipTags"`
												IPAddress      string `json:"ipAddress"`
												PublicIPPrefix struct {
													ID string `json:"id"`
												} `json:"publicIPPrefix"`
												IdleTimeoutInMinutes string `json:"idleTimeoutInMinutes"`
												ResourceGUID         string `json:"resourceGuid"`
											} `json:"properties"`
											Zones []string `json:"zones"`
										} `json:"publicIPAddress"`
										PublicIPPrefix struct {
											ID string `json:"id"`
										} `json:"publicIPPrefix"`
									} `json:"properties"`
									Name  string   `json:"name"`
									Zones []string `json:"zones"`
								} `json:"destinationLoadBalancerFrontEndIPConfiguration"`
								DestinationPort string `json:"destinationPort"`
							} `json:"properties"`
						} `json:"virtualNetworkTaps"`
						ApplicationGatewayBackendAddressPools []string `json:"applicationGatewayBackendAddressPools"`
						LoadBalancerBackendAddressPools       []struct {
							ID         string `json:"id"`
							Properties struct {
							} `json:"properties"`
							Name string `json:"name"`
						} `json:"loadBalancerBackendAddressPools"`
						LoadBalancerInboundNatRules []struct {
							ID         string `json:"id"`
							Properties struct {
								FrontendIPConfiguration struct {
									ID string `json:"id"`
								} `json:"frontendIPConfiguration"`
								Protocol             string `json:"protocol"`
								FrontendPort         string `json:"frontendPort"`
								BackendPort          string `json:"backendPort"`
								IdleTimeoutInMinutes string `json:"idleTimeoutInMinutes"`
								EnableFloatingIP     string `json:"enableFloatingIP"`
								EnableTCPReset       string `json:"enableTcpReset"`
							} `json:"properties"`
							Name string `json:"name"`
						} `json:"loadBalancerInboundNatRules"`
						PrivateIPAddress          string `json:"privateIPAddress"`
						PrivateIPAllocationMethod string `json:"privateIPAllocationMethod"`
						PrivateIPAddressVersion   string `json:"privateIPAddressVersion"`
						Subnet                    struct {
							ID         string `json:"id"`
							Properties struct {
								AddressPrefix        string   `json:"addressPrefix"`
								AddressPrefixes      []string `json:"addressPrefixes"`
								NetworkSecurityGroup struct {
									ID       string `json:"id"`
									Location string `json:"location"`
									Tags     struct {
									} `json:"tags"`
									Properties struct {
										SecurityRules []struct {
											ID         string `json:"id"`
											Properties struct {
												Description                     string   `json:"description"`
												Protocol                        string   `json:"protocol"`
												SourcePortRange                 string   `json:"sourcePortRange"`
												DestinationPortRange            string   `json:"destinationPortRange"`
												SourceAddressPrefix             string   `json:"sourceAddressPrefix"`
												SourceAddressPrefixes           []string `json:"sourceAddressPrefixes"`
												SourceApplicationSecurityGroups []struct {
													ID       string `json:"id"`
													Location string `json:"location"`
													Tags     struct {
													} `json:"tags"`
													Properties struct {
													} `json:"properties"`
												} `json:"sourceApplicationSecurityGroups"`
												DestinationAddressPrefix             string   `json:"destinationAddressPrefix"`
												DestinationAddressPrefixes           []string `json:"destinationAddressPrefixes"`
												DestinationApplicationSecurityGroups []struct {
													ID       string `json:"id"`
													Location string `json:"location"`
													Tags     struct {
													} `json:"tags"`
													Properties struct {
													} `json:"properties"`
												} `json:"destinationApplicationSecurityGroups"`
												SourcePortRanges      []string `json:"sourcePortRanges"`
												DestinationPortRanges []string `json:"destinationPortRanges"`
												Access                string   `json:"access"`
												Priority              string   `json:"priority"`
												Direction             string   `json:"direction"`
											} `json:"properties"`
											Name string `json:"name"`
										} `json:"securityRules"`
										DefaultSecurityRules []struct {
											ID         string `json:"id"`
											Properties struct {
												Description                     string   `json:"description"`
												Protocol                        string   `json:"protocol"`
												SourcePortRange                 string   `json:"sourcePortRange"`
												DestinationPortRange            string   `json:"destinationPortRange"`
												SourceAddressPrefix             string   `json:"sourceAddressPrefix"`
												SourceAddressPrefixes           []string `json:"sourceAddressPrefixes"`
												SourceApplicationSecurityGroups []struct {
													ID       string `json:"id"`
													Location string `json:"location"`
													Tags     struct {
													} `json:"tags"`
													Properties struct {
													} `json:"properties"`
												} `json:"sourceApplicationSecurityGroups"`
												DestinationAddressPrefix             string   `json:"destinationAddressPrefix"`
												DestinationAddressPrefixes           []string `json:"destinationAddressPrefixes"`
												DestinationApplicationSecurityGroups []struct {
													ID       string `json:"id"`
													Location string `json:"location"`
													Tags     struct {
													} `json:"tags"`
													Properties struct {
													} `json:"properties"`
												} `json:"destinationApplicationSecurityGroups"`
												SourcePortRanges      []string `json:"sourcePortRanges"`
												DestinationPortRanges []string `json:"destinationPortRanges"`
												Access                string   `json:"access"`
												Priority              string   `json:"priority"`
												Direction             string   `json:"direction"`
											} `json:"properties"`
											Name string `json:"name"`
										} `json:"defaultSecurityRules"`
										ResourceGUID string `json:"resourceGuid"`
									} `json:"properties"`
								} `json:"networkSecurityGroup"`
								RouteTable struct {
									ID       string `json:"id"`
									Location string `json:"location"`
									Tags     struct {
									} `json:"tags"`
									Properties struct {
										Routes []struct {
											ID         string `json:"id"`
											Properties struct {
												AddressPrefix    string `json:"addressPrefix"`
												NextHopType      string `json:"nextHopType"`
												NextHopIPAddress string `json:"nextHopIpAddress"`
											} `json:"properties"`
											Name string `json:"name"`
										} `json:"routes"`
										DisableBgpRoutePropagation string `json:"disableBgpRoutePropagation"`
									} `json:"properties"`
								} `json:"routeTable"`
								NatGateway struct {
									ID string `json:"id"`
								} `json:"natGateway"`
								ServiceEndpoints []struct {
									Service   string   `json:"service"`
									Locations []string `json:"locations"`
								} `json:"serviceEndpoints"`
								ServiceEndpointPolicies []struct {
									ID       string `json:"id"`
									Location string `json:"location"`
									Tags     struct {
									} `json:"tags"`
									Properties struct {
										ServiceEndpointPolicyDefinitions []struct {
											ID         string `json:"id"`
											Properties struct {
												Description      string   `json:"description"`
												Service          string   `json:"service"`
												ServiceResources []string `json:"serviceResources"`
											} `json:"properties"`
											Name string `json:"name"`
										} `json:"serviceEndpointPolicyDefinitions"`
									} `json:"properties"`
								} `json:"serviceEndpointPolicies"`
								ResourceNavigationLinks []struct {
									ID         string `json:"id"`
									Properties struct {
										LinkedResourceType string `json:"linkedResourceType"`
										Link               string `json:"link"`
									} `json:"properties"`
									Name string `json:"name"`
								} `json:"resourceNavigationLinks"`
								ServiceAssociationLinks []struct {
									ID         string `json:"id"`
									Properties struct {
										LinkedResourceType string `json:"linkedResourceType"`
										Link               string `json:"link"`
									} `json:"properties"`
									Name string `json:"name"`
								} `json:"serviceAssociationLinks"`
								Delegations []struct {
									ID         string `json:"id"`
									Properties struct {
										ServiceName string   `json:"serviceName"`
										Actions     []string `json:"actions"`
									} `json:"properties"`
									Name string `json:"name"`
								} `json:"delegations"`
							} `json:"properties"`
							Name string `json:"name"`
						} `json:"subnet"`
						Primary         string `json:"primary"`
						PublicIPAddress struct {
							ID       string `json:"id"`
							Location string `json:"location"`
							Tags     struct {
							} `json:"tags"`
							Sku struct {
								Name string `json:"name"`
							} `json:"sku"`
							Properties struct {
								PublicIPAllocationMethod string `json:"publicIPAllocationMethod"`
								PublicIPAddressVersion   string `json:"publicIPAddressVersion"`
								DNSSettings              struct {
									DomainNameLabel string `json:"domainNameLabel"`
									Fqdn            string `json:"fqdn"`
									ReverseFqdn     string `json:"reverseFqdn"`
								} `json:"dnsSettings"`
								DdosSettings struct {
									DdosCustomPolicy struct {
										ID string `json:"id"`
									} `json:"ddosCustomPolicy"`
									ProtectionCoverage string `json:"protectionCoverage"`
								} `json:"ddosSettings"`
								IPTags []struct {
									IPTagType string `json:"ipTagType"`
									Tag       string `json:"tag"`
								} `json:"ipTags"`
								IPAddress      string `json:"ipAddress"`
								PublicIPPrefix struct {
									ID string `json:"id"`
								} `json:"publicIPPrefix"`
								IdleTimeoutInMinutes string `json:"idleTimeoutInMinutes"`
								ResourceGUID         string `json:"resourceGuid"`
							} `json:"properties"`
							Zones []string `json:"zones"`
						} `json:"publicIPAddress"`
						ApplicationSecurityGroups []struct {
							ID       string `json:"id"`
							Location string `json:"location"`
							Tags     struct {
							} `json:"tags"`
							Properties struct {
							} `json:"properties"`
						} `json:"applicationSecurityGroups"`
					} `json:"properties"`
					Name string `json:"name"`
				} `json:"backendIPConfigurations"`
				BackendAddresses []struct {
					Fqdn      string `json:"fqdn"`
					IPAddress string `json:"ipAddress"`
				} `json:"backendAddresses"`
			} `json:"properties"`
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"backendAddressPools"`
		BackendHTTPSettingsCollection []struct {
			ID         string `json:"id"`
			Properties struct {
				Port                int    `json:"port"`
				Protocol            string `json:"protocol"`
				CookieBasedAffinity string `json:"cookieBasedAffinity"`
				RequestTimeout      int    `json:"requestTimeout"`
				Probe               struct {
					ID string `json:"id"`
				} `json:"probe"`
				AuthenticationCertificates []struct {
					ID string `json:"id"`
				} `json:"authenticationCertificates"`
				TrustedRootCertificates []struct {
					ID string `json:"id"`
				} `json:"trustedRootCertificates"`
				ConnectionDraining struct {
					Enabled           string `json:"enabled"`
					DrainTimeoutInSec string `json:"drainTimeoutInSec"`
				} `json:"connectionDraining"`
				HostName                       string `json:"hostName"`
				PickHostNameFromBackendAddress bool   `json:"pickHostNameFromBackendAddress"`
				AffinityCookieName             string `json:"affinityCookieName"`
				ProbeEnabled                   string `json:"probeEnabled"`
				Path                           string `json:"path"`
			} `json:"properties"`
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"backendHttpSettingsCollection"`
		HTTPListeners []struct {
			ID         string `json:"id"`
			Properties struct {
				FrontendIPConfiguration struct {
					ID string `json:"id"`
				} `json:"frontendIPConfiguration"`
				FrontendPort struct {
					ID string `json:"id"`
				} `json:"frontendPort"`
				Protocol       string `json:"protocol"`
				HostName       string `json:"hostName"`
				SslCertificate struct {
					ID string `json:"id"`
				} `json:"sslCertificate"`
				RequireServerNameIndication bool `json:"requireServerNameIndication"`
				CustomErrorConfigurations   []struct {
					StatusCode         string `json:"statusCode"`
					CustomErrorPageURL string `json:"customErrorPageUrl"`
				} `json:"customErrorConfigurations"`
			} `json:"properties"`
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"httpListeners"`
		URLPathMaps []struct {
			ID         string `json:"id"`
			Properties struct {
				DefaultBackendAddressPool struct {
					ID string `json:"id"`
				} `json:"defaultBackendAddressPool"`
				DefaultBackendHTTPSettings struct {
					ID string `json:"id"`
				} `json:"defaultBackendHttpSettings"`
				DefaultRewriteRuleSet struct {
					ID string `json:"id"`
				} `json:"defaultRewriteRuleSet"`
				DefaultRedirectConfiguration struct {
					ID string `json:"id"`
				} `json:"defaultRedirectConfiguration"`
				PathRules []struct {
					ID         string `json:"id"`
					Properties struct {
						Paths              []string `json:"paths"`
						BackendAddressPool struct {
							ID string `json:"id"`
						} `json:"backendAddressPool"`
						BackendHTTPSettings struct {
							ID string `json:"id"`
						} `json:"backendHttpSettings"`
						RedirectConfiguration struct {
							ID string `json:"id"`
						} `json:"redirectConfiguration"`
						RewriteRuleSet struct {
							ID string `json:"id"`
						} `json:"rewriteRuleSet"`
					} `json:"properties"`
					Name string `json:"name"`
					Type string `json:"type"`
				} `json:"pathRules"`
			} `json:"properties"`
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"urlPathMaps"`
		RequestRoutingRules []struct {
			ID         string `json:"id"`
			Properties struct {
				RuleType           string `json:"ruleType"`
				BackendAddressPool struct {
					ID string `json:"id"`
				} `json:"backendAddressPool"`
				BackendHTTPSettings struct {
					ID string `json:"id"`
				} `json:"backendHttpSettings"`
				HTTPListener struct {
					ID string `json:"id"`
				} `json:"httpListener"`
				URLPathMap struct {
					ID string `json:"id"`
				} `json:"urlPathMap"`
				RewriteRuleSet struct {
					ID string `json:"id"`
				} `json:"rewriteRuleSet"`
				RedirectConfiguration struct {
					ID string `json:"id"`
				} `json:"redirectConfiguration"`
			} `json:"properties"`
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"requestRoutingRules"`
		RewriteRuleSets []struct {
			ID         string `json:"id"`
			Properties struct {
				RewriteRules []struct {
					Name         string `json:"name"`
					RuleSequence int    `json:"ruleSequence"`
					Conditions   []struct {
						Variable   string `json:"variable"`
						Pattern    string `json:"pattern"`
						IgnoreCase bool   `json:"ignoreCase"`
						Negate     bool   `json:"negate"`
					} `json:"conditions"`
					ActionSet struct {
						RequestHeaderConfigurations []struct {
							HeaderName  string `json:"headerName"`
							HeaderValue string `json:"headerValue"`
						} `json:"requestHeaderConfigurations"`
						ResponseHeaderConfigurations []struct {
							HeaderName  string `json:"headerName"`
							HeaderValue string `json:"headerValue"`
						} `json:"responseHeaderConfigurations"`
					} `json:"actionSet"`
				} `json:"rewriteRules"`
			} `json:"properties"`
			Name string `json:"name"`
		} `json:"rewriteRuleSets"`
		RedirectConfigurations []struct {
			ID         string `json:"id"`
			Properties struct {
				RedirectType   string `json:"redirectType"`
				TargetListener struct {
					ID string `json:"id"`
				} `json:"targetListener"`
				TargetURL           string `json:"targetUrl"`
				IncludePath         bool   `json:"includePath"`
				IncludeQueryString  bool   `json:"includeQueryString"`
				RequestRoutingRules []struct {
					ID string `json:"id"`
				} `json:"requestRoutingRules"`
				URLPathMaps []struct {
					ID string `json:"id"`
				} `json:"urlPathMaps"`
				PathRules []struct {
					ID string `json:"id"`
				} `json:"pathRules"`
			} `json:"properties"`
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"redirectConfigurations"`
		WebApplicationFirewallConfiguration struct {
			Enabled            bool   `json:"enabled"`
			FirewallMode       string `json:"firewallMode"`
			RuleSetType        string `json:"ruleSetType"`
			RuleSetVersion     string `json:"ruleSetVersion"`
			DisabledRuleGroups []struct {
				RuleGroupName string `json:"ruleGroupName"`
				Rules         []int  `json:"rules"`
			} `json:"disabledRuleGroups"`
			RequestBodyCheck       bool `json:"requestBodyCheck"`
			MaxRequestBodySize     int  `json:"maxRequestBodySize"`
			MaxRequestBodySizeInKb int  `json:"maxRequestBodySizeInKb"`
			FileUploadLimitInMb    int  `json:"fileUploadLimitInMb"`
			Exclusions             []struct {
				MatchVariable         string `json:"matchVariable"`
				SelectorMatchOperator string `json:"selectorMatchOperator"`
				Selector              string `json:"selector"`
			} `json:"exclusions"`
		} `json:"webApplicationFirewallConfiguration"`
		FirewallPolicy struct {
			ID string `json:"id"`
		} `json:"firewallPolicy"`
		EnableHTTP2            bool   `json:"enableHttp2"`
		EnableFips             string `json:"enableFips"`
		AutoscaleConfiguration struct {
			MinCapacity int `json:"minCapacity"`
			MaxCapacity int `json:"maxCapacity"`
		} `json:"autoscaleConfiguration"`
		ResourceGUID              string `json:"resourceGuid"`
		CustomErrorConfigurations []struct {
			StatusCode         string `json:"statusCode"`
			CustomErrorPageURL string `json:"customErrorPageUrl"`
		} `json:"customErrorConfigurations"`
	} `json:"properties"`
	Zones    []string `json:"zones"`
	Identity struct {
		Type                   string `json:"type"`
		UserAssignedIdentities struct {
		} `json:"userAssignedIdentities"`
	} `json:"identity"`
}

type ApplicationGateways struct {
	Value []struct {
		Name       string `json:"name"`
		ID         string `json:"id"`
		Etag       string `json:"etag"`
		Type       string `json:"type"`
		APIVersion string `json:"apiVersion"`
		Location   string `json:"location"`
		Tags       struct {
		} `json:"tags"`
		Properties struct {
			Sku struct {
				Name     string `json:"name"`
				Tier     string `json:"tier"`
				Capacity int    `json:"capacity"`
			} `json:"sku"`
			SslPolicy struct {
				DisabledSslProtocols []string `json:"disabledSslProtocols"`
				PolicyType           string   `json:"policyType"`
				PolicyName           string   `json:"policyName"`
				CipherSuites         []string `json:"cipherSuites"`
				MinProtocolVersion   string   `json:"minProtocolVersion"`
			} `json:"sslPolicy"`
			GatewayIPConfigurations []struct {
				ID         string `json:"id"`
				Properties struct {
					Subnet struct {
						ID string `json:"id"`
					} `json:"subnet"`
				} `json:"properties"`
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"gatewayIPConfigurations"`
			AuthenticationCertificates []struct {
				ID         string `json:"id"`
				Properties struct {
					Data string `json:"data"`
				} `json:"properties"`
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"authenticationCertificates"`
			TrustedRootCertificates []struct {
				ID         string `json:"id"`
				Properties struct {
					Data             string `json:"data"`
					KeyVaultSecretID string `json:"keyVaultSecretId"`
				} `json:"properties"`
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"trustedRootCertificates"`
			SslCertificates []struct {
				ID         string `json:"id"`
				Properties struct {
					Data             string `json:"data"`
					Password         string `json:"password"`
					PublicCertData   string `json:"publicCertData"`
					KeyVaultSecretID string `json:"keyVaultSecretId"`
				} `json:"properties"`
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"sslCertificates"`
			FrontendIPConfigurations []struct {
				ID         string `json:"id"`
				Properties struct {
					PrivateIPAddress          string `json:"privateIPAddress"`
					PrivateIPAllocationMethod string `json:"privateIPAllocationMethod"`
					Subnet                    struct {
						ID string `json:"id"`
					} `json:"subnet"`
					PublicIPAddress struct {
						ID string `json:"id"`
					} `json:"publicIPAddress"`
				} `json:"properties"`
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"frontendIPConfigurations"`
			FrontendPorts []struct {
				ID         string `json:"id"`
				Properties struct {
					Port int `json:"port"`
				} `json:"properties"`
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"frontendPorts"`
			Probes []struct {
				ID         string `json:"id"`
				Properties struct {
					Protocol                            string `json:"protocol"`
					Host                                string `json:"host"`
					Path                                string `json:"path"`
					Interval                            int    `json:"interval"`
					Timeout                             int    `json:"timeout"`
					UnhealthyThreshold                  int    `json:"unhealthyThreshold"`
					PickHostNameFromBackendHTTPSettings bool   `json:"pickHostNameFromBackendHttpSettings"`
					MinServers                          int    `json:"minServers"`
					Match                               struct {
						Body        string   `json:"body"`
						StatusCodes []string `json:"statusCodes"`
					} `json:"match"`
				} `json:"properties"`
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"probes"`
			BackendAddressPools []struct {
				ID         string `json:"id"`
				Properties struct {
					BackendIPConfigurations []struct {
						ID         string `json:"id"`
						Properties struct {
							VirtualNetworkTaps []struct {
								ID       string `json:"id"`
								Location string `json:"location"`
								Tags     struct {
								} `json:"tags"`
								Properties struct {
									DestinationNetworkInterfaceIPConfiguration     string `json:"destinationNetworkInterfaceIPConfiguration"`
									DestinationLoadBalancerFrontEndIPConfiguration struct {
										ID         string `json:"id"`
										Properties struct {
											PrivateIPAddress          string `json:"privateIPAddress"`
											PrivateIPAllocationMethod string `json:"privateIPAllocationMethod"`
											Subnet                    struct {
												ID         string `json:"id"`
												Properties struct {
													AddressPrefix        string   `json:"addressPrefix"`
													AddressPrefixes      []string `json:"addressPrefixes"`
													NetworkSecurityGroup struct {
														ID       string `json:"id"`
														Location string `json:"location"`
														Tags     struct {
														} `json:"tags"`
														Properties struct {
															SecurityRules []struct {
																ID         string `json:"id"`
																Properties struct {
																	Description                     string   `json:"description"`
																	Protocol                        string   `json:"protocol"`
																	SourcePortRange                 string   `json:"sourcePortRange"`
																	DestinationPortRange            string   `json:"destinationPortRange"`
																	SourceAddressPrefix             string   `json:"sourceAddressPrefix"`
																	SourceAddressPrefixes           []string `json:"sourceAddressPrefixes"`
																	SourceApplicationSecurityGroups []struct {
																		ID       string `json:"id"`
																		Location string `json:"location"`
																		Tags     struct {
																		} `json:"tags"`
																		Properties struct {
																		} `json:"properties"`
																	} `json:"sourceApplicationSecurityGroups"`
																	DestinationAddressPrefix             string   `json:"destinationAddressPrefix"`
																	DestinationAddressPrefixes           []string `json:"destinationAddressPrefixes"`
																	DestinationApplicationSecurityGroups []struct {
																		ID       string `json:"id"`
																		Location string `json:"location"`
																		Tags     struct {
																		} `json:"tags"`
																		Properties struct {
																		} `json:"properties"`
																	} `json:"destinationApplicationSecurityGroups"`
																	SourcePortRanges      []string `json:"sourcePortRanges"`
																	DestinationPortRanges []string `json:"destinationPortRanges"`
																	Access                string   `json:"access"`
																	Priority              string   `json:"priority"`
																	Direction             string   `json:"direction"`
																} `json:"properties"`
																Name string `json:"name"`
															} `json:"securityRules"`
															DefaultSecurityRules []struct {
																ID         string `json:"id"`
																Properties struct {
																	Description                     string   `json:"description"`
																	Protocol                        string   `json:"protocol"`
																	SourcePortRange                 string   `json:"sourcePortRange"`
																	DestinationPortRange            string   `json:"destinationPortRange"`
																	SourceAddressPrefix             string   `json:"sourceAddressPrefix"`
																	SourceAddressPrefixes           []string `json:"sourceAddressPrefixes"`
																	SourceApplicationSecurityGroups []struct {
																		ID       string `json:"id"`
																		Location string `json:"location"`
																		Tags     struct {
																		} `json:"tags"`
																		Properties struct {
																		} `json:"properties"`
																	} `json:"sourceApplicationSecurityGroups"`
																	DestinationAddressPrefix             string   `json:"destinationAddressPrefix"`
																	DestinationAddressPrefixes           []string `json:"destinationAddressPrefixes"`
																	DestinationApplicationSecurityGroups []struct {
																		ID       string `json:"id"`
																		Location string `json:"location"`
																		Tags     struct {
																		} `json:"tags"`
																		Properties struct {
																		} `json:"properties"`
																	} `json:"destinationApplicationSecurityGroups"`
																	SourcePortRanges      []string `json:"sourcePortRanges"`
																	DestinationPortRanges []string `json:"destinationPortRanges"`
																	Access                string   `json:"access"`
																	Priority              string   `json:"priority"`
																	Direction             string   `json:"direction"`
																} `json:"properties"`
																Name string `json:"name"`
															} `json:"defaultSecurityRules"`
															ResourceGUID string `json:"resourceGuid"`
														} `json:"properties"`
													} `json:"networkSecurityGroup"`
													RouteTable struct {
														ID       string `json:"id"`
														Location string `json:"location"`
														Tags     struct {
														} `json:"tags"`
														Properties struct {
															Routes []struct {
																ID         string `json:"id"`
																Properties struct {
																	AddressPrefix    string `json:"addressPrefix"`
																	NextHopType      string `json:"nextHopType"`
																	NextHopIPAddress string `json:"nextHopIpAddress"`
																} `json:"properties"`
																Name string `json:"name"`
															} `json:"routes"`
															DisableBgpRoutePropagation string `json:"disableBgpRoutePropagation"`
														} `json:"properties"`
													} `json:"routeTable"`
													NatGateway struct {
														ID string `json:"id"`
													} `json:"natGateway"`
													ServiceEndpoints []struct {
														Service   string   `json:"service"`
														Locations []string `json:"locations"`
													} `json:"serviceEndpoints"`
													ServiceEndpointPolicies []struct {
														ID       string `json:"id"`
														Location string `json:"location"`
														Tags     struct {
														} `json:"tags"`
														Properties struct {
															ServiceEndpointPolicyDefinitions []struct {
																ID         string `json:"id"`
																Properties struct {
																	Description      string   `json:"description"`
																	Service          string   `json:"service"`
																	ServiceResources []string `json:"serviceResources"`
																} `json:"properties"`
																Name string `json:"name"`
															} `json:"serviceEndpointPolicyDefinitions"`
														} `json:"properties"`
													} `json:"serviceEndpointPolicies"`
													ResourceNavigationLinks []struct {
														ID         string `json:"id"`
														Properties struct {
															LinkedResourceType string `json:"linkedResourceType"`
															Link               string `json:"link"`
														} `json:"properties"`
														Name string `json:"name"`
													} `json:"resourceNavigationLinks"`
													ServiceAssociationLinks []struct {
														ID         string `json:"id"`
														Properties struct {
															LinkedResourceType string `json:"linkedResourceType"`
															Link               string `json:"link"`
														} `json:"properties"`
														Name string `json:"name"`
													} `json:"serviceAssociationLinks"`
													Delegations []struct {
														ID         string `json:"id"`
														Properties struct {
															ServiceName string   `json:"serviceName"`
															Actions     []string `json:"actions"`
														} `json:"properties"`
														Name string `json:"name"`
													} `json:"delegations"`
												} `json:"properties"`
												Name string `json:"name"`
											} `json:"subnet"`
											PublicIPAddress struct {
												ID       string `json:"id"`
												Location string `json:"location"`
												Tags     struct {
												} `json:"tags"`
												Sku struct {
													Name string `json:"name"`
												} `json:"sku"`
												Properties struct {
													PublicIPAllocationMethod string `json:"publicIPAllocationMethod"`
													PublicIPAddressVersion   string `json:"publicIPAddressVersion"`
													DNSSettings              struct {
														DomainNameLabel string `json:"domainNameLabel"`
														Fqdn            string `json:"fqdn"`
														ReverseFqdn     string `json:"reverseFqdn"`
													} `json:"dnsSettings"`
													DdosSettings struct {
														DdosCustomPolicy struct {
															ID string `json:"id"`
														} `json:"ddosCustomPolicy"`
														ProtectionCoverage string `json:"protectionCoverage"`
													} `json:"ddosSettings"`
													IPTags []struct {
														IPTagType string `json:"ipTagType"`
														Tag       string `json:"tag"`
													} `json:"ipTags"`
													IPAddress      string `json:"ipAddress"`
													PublicIPPrefix struct {
														ID string `json:"id"`
													} `json:"publicIPPrefix"`
													IdleTimeoutInMinutes string `json:"idleTimeoutInMinutes"`
													ResourceGUID         string `json:"resourceGuid"`
												} `json:"properties"`
												Zones []string `json:"zones"`
											} `json:"publicIPAddress"`
											PublicIPPrefix struct {
												ID string `json:"id"`
											} `json:"publicIPPrefix"`
										} `json:"properties"`
										Name  string   `json:"name"`
										Zones []string `json:"zones"`
									} `json:"destinationLoadBalancerFrontEndIPConfiguration"`
									DestinationPort string `json:"destinationPort"`
								} `json:"properties"`
							} `json:"virtualNetworkTaps"`
							ApplicationGatewayBackendAddressPools []string `json:"applicationGatewayBackendAddressPools"`
							LoadBalancerBackendAddressPools       []struct {
								ID         string `json:"id"`
								Properties struct {
								} `json:"properties"`
								Name string `json:"name"`
							} `json:"loadBalancerBackendAddressPools"`
							LoadBalancerInboundNatRules []struct {
								ID         string `json:"id"`
								Properties struct {
									FrontendIPConfiguration struct {
										ID string `json:"id"`
									} `json:"frontendIPConfiguration"`
									Protocol             string `json:"protocol"`
									FrontendPort         string `json:"frontendPort"`
									BackendPort          string `json:"backendPort"`
									IdleTimeoutInMinutes string `json:"idleTimeoutInMinutes"`
									EnableFloatingIP     string `json:"enableFloatingIP"`
									EnableTCPReset       string `json:"enableTcpReset"`
								} `json:"properties"`
								Name string `json:"name"`
							} `json:"loadBalancerInboundNatRules"`
							PrivateIPAddress          string `json:"privateIPAddress"`
							PrivateIPAllocationMethod string `json:"privateIPAllocationMethod"`
							PrivateIPAddressVersion   string `json:"privateIPAddressVersion"`
							Subnet                    struct {
								ID         string `json:"id"`
								Properties struct {
									AddressPrefix        string   `json:"addressPrefix"`
									AddressPrefixes      []string `json:"addressPrefixes"`
									NetworkSecurityGroup struct {
										ID       string `json:"id"`
										Location string `json:"location"`
										Tags     struct {
										} `json:"tags"`
										Properties struct {
											SecurityRules []struct {
												ID         string `json:"id"`
												Properties struct {
													Description                     string   `json:"description"`
													Protocol                        string   `json:"protocol"`
													SourcePortRange                 string   `json:"sourcePortRange"`
													DestinationPortRange            string   `json:"destinationPortRange"`
													SourceAddressPrefix             string   `json:"sourceAddressPrefix"`
													SourceAddressPrefixes           []string `json:"sourceAddressPrefixes"`
													SourceApplicationSecurityGroups []struct {
														ID       string `json:"id"`
														Location string `json:"location"`
														Tags     struct {
														} `json:"tags"`
														Properties struct {
														} `json:"properties"`
													} `json:"sourceApplicationSecurityGroups"`
													DestinationAddressPrefix             string   `json:"destinationAddressPrefix"`
													DestinationAddressPrefixes           []string `json:"destinationAddressPrefixes"`
													DestinationApplicationSecurityGroups []struct {
														ID       string `json:"id"`
														Location string `json:"location"`
														Tags     struct {
														} `json:"tags"`
														Properties struct {
														} `json:"properties"`
													} `json:"destinationApplicationSecurityGroups"`
													SourcePortRanges      []string `json:"sourcePortRanges"`
													DestinationPortRanges []string `json:"destinationPortRanges"`
													Access                string   `json:"access"`
													Priority              string   `json:"priority"`
													Direction             string   `json:"direction"`
												} `json:"properties"`
												Name string `json:"name"`
											} `json:"securityRules"`
											DefaultSecurityRules []struct {
												ID         string `json:"id"`
												Properties struct {
													Description                     string   `json:"description"`
													Protocol                        string   `json:"protocol"`
													SourcePortRange                 string   `json:"sourcePortRange"`
													DestinationPortRange            string   `json:"destinationPortRange"`
													SourceAddressPrefix             string   `json:"sourceAddressPrefix"`
													SourceAddressPrefixes           []string `json:"sourceAddressPrefixes"`
													SourceApplicationSecurityGroups []struct {
														ID       string `json:"id"`
														Location string `json:"location"`
														Tags     struct {
														} `json:"tags"`
														Properties struct {
														} `json:"properties"`
													} `json:"sourceApplicationSecurityGroups"`
													DestinationAddressPrefix             string   `json:"destinationAddressPrefix"`
													DestinationAddressPrefixes           []string `json:"destinationAddressPrefixes"`
													DestinationApplicationSecurityGroups []struct {
														ID       string `json:"id"`
														Location string `json:"location"`
														Tags     struct {
														} `json:"tags"`
														Properties struct {
														} `json:"properties"`
													} `json:"destinationApplicationSecurityGroups"`
													SourcePortRanges      []string `json:"sourcePortRanges"`
													DestinationPortRanges []string `json:"destinationPortRanges"`
													Access                string   `json:"access"`
													Priority              string   `json:"priority"`
													Direction             string   `json:"direction"`
												} `json:"properties"`
												Name string `json:"name"`
											} `json:"defaultSecurityRules"`
											ResourceGUID string `json:"resourceGuid"`
										} `json:"properties"`
									} `json:"networkSecurityGroup"`
									RouteTable struct {
										ID       string `json:"id"`
										Location string `json:"location"`
										Tags     struct {
										} `json:"tags"`
										Properties struct {
											Routes []struct {
												ID         string `json:"id"`
												Properties struct {
													AddressPrefix    string `json:"addressPrefix"`
													NextHopType      string `json:"nextHopType"`
													NextHopIPAddress string `json:"nextHopIpAddress"`
												} `json:"properties"`
												Name string `json:"name"`
											} `json:"routes"`
											DisableBgpRoutePropagation string `json:"disableBgpRoutePropagation"`
										} `json:"properties"`
									} `json:"routeTable"`
									NatGateway struct {
										ID string `json:"id"`
									} `json:"natGateway"`
									ServiceEndpoints []struct {
										Service   string   `json:"service"`
										Locations []string `json:"locations"`
									} `json:"serviceEndpoints"`
									ServiceEndpointPolicies []struct {
										ID       string `json:"id"`
										Location string `json:"location"`
										Tags     struct {
										} `json:"tags"`
										Properties struct {
											ServiceEndpointPolicyDefinitions []struct {
												ID         string `json:"id"`
												Properties struct {
													Description      string   `json:"description"`
													Service          string   `json:"service"`
													ServiceResources []string `json:"serviceResources"`
												} `json:"properties"`
												Name string `json:"name"`
											} `json:"serviceEndpointPolicyDefinitions"`
										} `json:"properties"`
									} `json:"serviceEndpointPolicies"`
									ResourceNavigationLinks []struct {
										ID         string `json:"id"`
										Properties struct {
											LinkedResourceType string `json:"linkedResourceType"`
											Link               string `json:"link"`
										} `json:"properties"`
										Name string `json:"name"`
									} `json:"resourceNavigationLinks"`
									ServiceAssociationLinks []struct {
										ID         string `json:"id"`
										Properties struct {
											LinkedResourceType string `json:"linkedResourceType"`
											Link               string `json:"link"`
										} `json:"properties"`
										Name string `json:"name"`
									} `json:"serviceAssociationLinks"`
									Delegations []struct {
										ID         string `json:"id"`
										Properties struct {
											ServiceName string   `json:"serviceName"`
											Actions     []string `json:"actions"`
										} `json:"properties"`
										Name string `json:"name"`
									} `json:"delegations"`
								} `json:"properties"`
								Name string `json:"name"`
							} `json:"subnet"`
							Primary         string `json:"primary"`
							PublicIPAddress struct {
								ID       string `json:"id"`
								Location string `json:"location"`
								Tags     struct {
								} `json:"tags"`
								Sku struct {
									Name string `json:"name"`
								} `json:"sku"`
								Properties struct {
									PublicIPAllocationMethod string `json:"publicIPAllocationMethod"`
									PublicIPAddressVersion   string `json:"publicIPAddressVersion"`
									DNSSettings              struct {
										DomainNameLabel string `json:"domainNameLabel"`
										Fqdn            string `json:"fqdn"`
										ReverseFqdn     string `json:"reverseFqdn"`
									} `json:"dnsSettings"`
									DdosSettings struct {
										DdosCustomPolicy struct {
											ID string `json:"id"`
										} `json:"ddosCustomPolicy"`
										ProtectionCoverage string `json:"protectionCoverage"`
									} `json:"ddosSettings"`
									IPTags []struct {
										IPTagType string `json:"ipTagType"`
										Tag       string `json:"tag"`
									} `json:"ipTags"`
									IPAddress      string `json:"ipAddress"`
									PublicIPPrefix struct {
										ID string `json:"id"`
									} `json:"publicIPPrefix"`
									IdleTimeoutInMinutes string `json:"idleTimeoutInMinutes"`
									ResourceGUID         string `json:"resourceGuid"`
								} `json:"properties"`
								Zones []string `json:"zones"`
							} `json:"publicIPAddress"`
							ApplicationSecurityGroups []struct {
								ID       string `json:"id"`
								Location string `json:"location"`
								Tags     struct {
								} `json:"tags"`
								Properties struct {
								} `json:"properties"`
							} `json:"applicationSecurityGroups"`
						} `json:"properties"`
						Name string `json:"name"`
					} `json:"backendIPConfigurations"`
					BackendAddresses []struct {
						Fqdn      string `json:"fqdn"`
						IPAddress string `json:"ipAddress"`
					} `json:"backendAddresses"`
				} `json:"properties"`
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"backendAddressPools"`
			BackendHTTPSettingsCollection []struct {
				ID         string `json:"id"`
				Properties struct {
					Port                int    `json:"port"`
					Protocol            string `json:"protocol"`
					CookieBasedAffinity string `json:"cookieBasedAffinity"`
					RequestTimeout      int    `json:"requestTimeout"`
					Probe               struct {
						ID string `json:"id"`
					} `json:"probe"`
					AuthenticationCertificates []struct {
						ID string `json:"id"`
					} `json:"authenticationCertificates"`
					TrustedRootCertificates []struct {
						ID string `json:"id"`
					} `json:"trustedRootCertificates"`
					ConnectionDraining struct {
						Enabled           string `json:"enabled"`
						DrainTimeoutInSec string `json:"drainTimeoutInSec"`
					} `json:"connectionDraining"`
					HostName                       string `json:"hostName"`
					PickHostNameFromBackendAddress bool   `json:"pickHostNameFromBackendAddress"`
					AffinityCookieName             string `json:"affinityCookieName"`
					ProbeEnabled                   string `json:"probeEnabled"`
					Path                           string `json:"path"`
				} `json:"properties"`
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"backendHttpSettingsCollection"`
			HTTPListeners []struct {
				ID         string `json:"id"`
				Properties struct {
					FrontendIPConfiguration struct {
						ID string `json:"id"`
					} `json:"frontendIPConfiguration"`
					FrontendPort struct {
						ID string `json:"id"`
					} `json:"frontendPort"`
					Protocol       string `json:"protocol"`
					HostName       string `json:"hostName"`
					SslCertificate struct {
						ID string `json:"id"`
					} `json:"sslCertificate"`
					RequireServerNameIndication bool `json:"requireServerNameIndication"`
					CustomErrorConfigurations   []struct {
						StatusCode         string `json:"statusCode"`
						CustomErrorPageURL string `json:"customErrorPageUrl"`
					} `json:"customErrorConfigurations"`
				} `json:"properties"`
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"httpListeners"`
			URLPathMaps []struct {
				ID         string `json:"id"`
				Properties struct {
					DefaultBackendAddressPool struct {
						ID string `json:"id"`
					} `json:"defaultBackendAddressPool"`
					DefaultBackendHTTPSettings struct {
						ID string `json:"id"`
					} `json:"defaultBackendHttpSettings"`
					DefaultRewriteRuleSet struct {
						ID string `json:"id"`
					} `json:"defaultRewriteRuleSet"`
					DefaultRedirectConfiguration struct {
						ID string `json:"id"`
					} `json:"defaultRedirectConfiguration"`
					PathRules []struct {
						ID         string `json:"id"`
						Properties struct {
							Paths              []string `json:"paths"`
							BackendAddressPool struct {
								ID string `json:"id"`
							} `json:"backendAddressPool"`
							BackendHTTPSettings struct {
								ID string `json:"id"`
							} `json:"backendHttpSettings"`
							RedirectConfiguration struct {
								ID string `json:"id"`
							} `json:"redirectConfiguration"`
							RewriteRuleSet struct {
								ID string `json:"id"`
							} `json:"rewriteRuleSet"`
						} `json:"properties"`
						Name string `json:"name"`
						Type string `json:"type"`
					} `json:"pathRules"`
				} `json:"properties"`
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"urlPathMaps"`
			RequestRoutingRules []struct {
				ID         string `json:"id"`
				Properties struct {
					RuleType           string `json:"ruleType"`
					BackendAddressPool struct {
						ID string `json:"id"`
					} `json:"backendAddressPool"`
					BackendHTTPSettings struct {
						ID string `json:"id"`
					} `json:"backendHttpSettings"`
					HTTPListener struct {
						ID string `json:"id"`
					} `json:"httpListener"`
					URLPathMap struct {
						ID string `json:"id"`
					} `json:"urlPathMap"`
					RewriteRuleSet struct {
						ID string `json:"id"`
					} `json:"rewriteRuleSet"`
					RedirectConfiguration struct {
						ID string `json:"id"`
					} `json:"redirectConfiguration"`
				} `json:"properties"`
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"requestRoutingRules"`
			RewriteRuleSets []struct {
				ID         string `json:"id"`
				Properties struct {
					RewriteRules []struct {
						Name         string `json:"name"`
						RuleSequence int    `json:"ruleSequence"`
						Conditions   []struct {
							Variable   string `json:"variable"`
							Pattern    string `json:"pattern"`
							IgnoreCase bool   `json:"ignoreCase"`
							Negate     bool   `json:"negate"`
						} `json:"conditions"`
						ActionSet struct {
							RequestHeaderConfigurations []struct {
								HeaderName  string `json:"headerName"`
								HeaderValue string `json:"headerValue"`
							} `json:"requestHeaderConfigurations"`
							ResponseHeaderConfigurations []struct {
								HeaderName  string `json:"headerName"`
								HeaderValue string `json:"headerValue"`
							} `json:"responseHeaderConfigurations"`
						} `json:"actionSet"`
					} `json:"rewriteRules"`
				} `json:"properties"`
				Name string `json:"name"`
			} `json:"rewriteRuleSets"`
			RedirectConfigurations []struct {
				ID         string `json:"id"`
				Properties struct {
					RedirectType   string `json:"redirectType"`
					TargetListener struct {
						ID string `json:"id"`
					} `json:"targetListener"`
					TargetURL           string `json:"targetUrl"`
					IncludePath         bool   `json:"includePath"`
					IncludeQueryString  bool   `json:"includeQueryString"`
					RequestRoutingRules []struct {
						ID string `json:"id"`
					} `json:"requestRoutingRules"`
					URLPathMaps []struct {
						ID string `json:"id"`
					} `json:"urlPathMaps"`
					PathRules []struct {
						ID string `json:"id"`
					} `json:"pathRules"`
				} `json:"properties"`
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"redirectConfigurations"`
			WebApplicationFirewallConfiguration struct {
				Enabled            bool   `json:"enabled"`
				FirewallMode       string `json:"firewallMode"`
				RuleSetType        string `json:"ruleSetType"`
				RuleSetVersion     string `json:"ruleSetVersion"`
				DisabledRuleGroups []struct {
					RuleGroupName string `json:"ruleGroupName"`
					Rules         []int  `json:"rules"`
				} `json:"disabledRuleGroups"`
				RequestBodyCheck       bool `json:"requestBodyCheck"`
				MaxRequestBodySize     int  `json:"maxRequestBodySize"`
				MaxRequestBodySizeInKb int  `json:"maxRequestBodySizeInKb"`
				FileUploadLimitInMb    int  `json:"fileUploadLimitInMb"`
				Exclusions             []struct {
					MatchVariable         string `json:"matchVariable"`
					SelectorMatchOperator string `json:"selectorMatchOperator"`
					Selector              string `json:"selector"`
				} `json:"exclusions"`
			} `json:"webApplicationFirewallConfiguration"`
			FirewallPolicy struct {
				ID string `json:"id"`
			} `json:"firewallPolicy"`
			EnableHTTP2            bool   `json:"enableHttp2"`
			EnableFips             string `json:"enableFips"`
			AutoscaleConfiguration struct {
				MinCapacity int `json:"minCapacity"`
				MaxCapacity int `json:"maxCapacity"`
			} `json:"autoscaleConfiguration"`
			ResourceGUID              string `json:"resourceGuid"`
			CustomErrorConfigurations []struct {
				StatusCode         string `json:"statusCode"`
				CustomErrorPageURL string `json:"customErrorPageUrl"`
			} `json:"customErrorConfigurations"`
		} `json:"properties"`
		Zones    []string `json:"zones"`
		Identity struct {
			Type                   string `json:"type"`
			UserAssignedIdentities struct {
			} `json:"userAssignedIdentities"`
		} `json:"identity"`
	} `json:"value"`
}
