package commands_test

import (
	"errors"

	"github.com/cloudfoundry/bosh-bootloader/commands"
	"github.com/cloudfoundry/bosh-bootloader/fakes"
	"github.com/cloudfoundry/bosh-bootloader/storage"
	"github.com/cloudfoundry/bosh-bootloader/terraform"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Outputs", func() {
	var (
		outputsCommand   commands.Outputs
		stateValidator   *fakes.StateValidator
		logger           *fakes.Logger
		terraformManager *fakes.TerraformManager
	)

	BeforeEach(func() {
		stateValidator = &fakes.StateValidator{}
		logger = &fakes.Logger{}
		terraformManager = &fakes.TerraformManager{}
		outputsCommand = commands.NewOutputs(logger, terraformManager, stateValidator)
	})

	Describe("CheckFastFails", func() {
		Context("when state validation fails", func() {
			BeforeEach(func() {
				stateValidator.ValidateCall.Returns.Error = errors.New("state validation failed")
			})

			It("returns an error", func() {
				err := outputsCommand.CheckFastFails([]string{}, storage.State{})

				Expect(stateValidator.ValidateCall.CallCount).To(Equal(1))
				Expect(err).To(MatchError("state validation failed"))
			})
		})
	})

	Describe("Execute", func() {
		It("prints the terraform outputs", func() {
			terraformOutputs := terraform.Outputs{
				Map: map[string]interface{}{
					"firewall": "cidr",
					"external": "address",
				},
			}
			terraformManager.GetOutputsCall.Returns.Outputs = terraformOutputs
			err := outputsCommand.Execute([]string{}, storage.State{})
			Expect(err).NotTo(HaveOccurred())
			Expect(logger.PrintfCall.Messages).To(ConsistOf([]string{
				"firewall: cidr\n",
				"external: address\n",
			}))
		})

		Context("failure cases", func() {
			Context("when getOutputs failes", func() {
				It("returns an error", func() {
					terraformManager.GetOutputsCall.Returns.Error = errors.New("tangelo")

					err := outputsCommand.Execute([]string{}, storage.State{})

					Expect(err).To(MatchError("tangelo"))
				})
			})
		})
	})
})
