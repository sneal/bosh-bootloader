package azure

import (
	"errors"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/arm/resources/resources"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	azurelib "github.com/Azure/go-autorest/autorest/azure"
)

type resource interface {
	List(filter string) ([]Deletable, error)
}

type Leftovers struct {
	logger    logger
	resources []resource
}

func (l Leftovers) Delete(filter string) error {
	var deletables []Deletable

	for _, r := range l.resources {
		list, err := r.List(filter)
		if err != nil {
			return err
		}

		deletables = append(deletables, list...)
	}

	for _, d := range deletables {
		l.logger.Println(fmt.Sprintf("Deleting %s.", d.Name()))

		if err := d.Delete(); err != nil {
			l.logger.Println(err.Error())
		} else {
			l.logger.Printf("SUCCESS deleting %s!\n", d.Name())
		}
	}

	return nil
}

func NewLeftovers(logger logger, clientId, clientSecret, subscriptionId, tenantId string) (Leftovers, error) {
	if clientId == "" {
		return Leftovers{}, errors.New("Missing client id.")
	}

	if clientSecret == "" {
		return Leftovers{}, errors.New("Missing client secret.")
	}

	if subscriptionId == "" {
		return Leftovers{}, errors.New("Missing subscription id.")
	}

	if tenantId == "" {
		return Leftovers{}, errors.New("Missing tenant id.")
	}

	oauthConfig, err := adal.NewOAuthConfig(azurelib.PublicCloud.ActiveDirectoryEndpoint, tenantId)
	if err != nil {
		return Leftovers{}, fmt.Errorf("Creating oauth config: %s\n", err)
	}

	servicePrincipalToken, err := adal.NewServicePrincipalToken(*oauthConfig, clientId, clientSecret, azurelib.PublicCloud.ResourceManagerEndpoint)
	if err != nil {
		return Leftovers{}, fmt.Errorf("Creating service principal token: %s\n", err)
	}

	gc := resources.NewGroupsClient(subscriptionId)
	gc.ManagementClient.Authorizer = autorest.NewBearerAuthorizer(servicePrincipalToken)

	return Leftovers{
		logger:    logger,
		resources: []resource{NewGroups(gc, logger)},
	}, nil
}
