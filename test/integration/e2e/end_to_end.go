/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package e2e

import (
	"github.com/hyperledger/fabric-sdk-go/test/metadata"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/errors/retry"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/fabric-sdk-go/test/integration"
	"github.com/hyperledger/fabric-sdk-go/third_party/github.com/hyperledger/fabric/common/cauthdsl"

	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"

	mspclient "github.com/hyperledger/fabric-sdk-go/pkg/client/msp"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	packager "github.com/hyperledger/fabric-sdk-go/pkg/fab/ccpackager/gopackager"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
)

const (
	channelID      = "mychannel"
	orgName        = "Org1"
	orgAdmin       = "Admin"
	ordererOrgName = "OrdererOrg"
)

var (
	//ccID = "example_cc_e2e" + metadata.TestRunID
	ccID = "example_cc_press_query_test" + metadata.TestRunID
)

// Run enables testing an end-to-end scenario against the supplied SDK options
func Run(t *testing.T, configOpt core.ConfigProvider, sdkOpts ...fabsdk.Option) {
	setupAndRun(t, false, configOpt, e2eTest, "invoke", sdkOpts...)
}

// Run enables testing an end-to-end scenario against the supplied SDK options
func Query(t *testing.T, configOpt core.ConfigProvider, sdkOpts ...fabsdk.Option) {
	if integration.IsLocal() {
		//If it is a local test then add entity mapping to config backend to parse URLs
		configOpt = integration.AddLocalEntityMapping(configOpt)
	}

	sdk, err := fabsdk.New(configOpt, sdkOpts...)
	if err != nil {
		t.Fatalf("Failed to create new SDK: %s", err)
	}
	defer sdk.Close()

	// Delete all private keys from the crypto suite store
	// and users from the user store at the end
	integration.CleanupUserData(t, sdk)
	defer integration.CleanupUserData(t, sdk)

	clientChannelContext := sdk.ChannelContext(channelID, fabsdk.WithUser("User1"), fabsdk.WithOrg(orgName))
	// Channel client is used to query and execute transactions (Org1 is default org)
	client, err := channel.New(clientChannelContext)
	if err != nil {
		t.Fatalf("Failed to create new channel client: %s", err)
	}

	//moveFunds(t, client)
	queryCC(t, client, "21000000169")

}

func PressTest(t *testing.T, configOpt core.ConfigProvider, sdkOpts ...fabsdk.Option) {
	pressTime := 200
	nprocess := 350
	lastTime := time.Now().UnixNano()
	successCount := 0
	var lock sync.RWMutex
	stopCh := make(chan struct{})

	for i := 0; i < nprocess; i++ {
		go func(index int) {
			count := 0
			key := int64(index * 1e8)
			for {
				// Move funds
				select {
				case <-stopCh:
					lock.Lock()
					successCount = successCount + count
					lock.Unlock()
					t.Logf("Tx Routine force closed id:(%d) , count:(%d) ,successCount:(%d) , lastKey:(%d)\n", i, count, successCount, key)
					return
				default:
				}

				setupAndRun(t, false, configOpt, e2eTest, strconv.FormatInt(key, 10), sdkOpts...)

				count++
				key++
				//t.Logf("count: %#v", count)
			}
		}(i)
	}

	for {
		currentTime := time.Now().UnixNano()
		if currentTime-lastTime > int64(pressTime)*1e9 {
			close(stopCh)
			time.Sleep(time.Second)
			t.Logf("time: %#v , concurrency: %#v, test case: invoke ,success count: %#v ,tps: %#v\n",
				(currentTime-lastTime)/1e9, nprocess, successCount, float64(successCount)/float64(pressTime))
			return
		}
		time.Sleep(time.Millisecond)
	}
}

//func PressTest(t *testing.T, configOpt core.ConfigProvider, sdkOpts ...fabsdk.Option) {
//	pressTime := 300
//	nprocess := 500
//	lastTime := time.Now().UnixNano()
//
//	successCount := 0
//	//var lockSuccess sync.RWMutex
//	//
//	//totalCount := 0
//	//var lockTotal sync.RWMutex
//
//	stopCh := make(chan struct{})
//
//	sdk, err := fabsdk.New(configOpt, sdkOpts...)
//	if err != nil {
//		t.Fatalf("Failed to create new SDK: %s", err)
//	}
//	defer sdk.Close()
//	// Delete all private keys from the crypto suite store
//	// and users from the user store at the end
//	integration.CleanupUserData(t, sdk)
//	defer integration.CleanupUserData(t, sdk)
//
//	clientChannelContext := sdk.ChannelContext(channelID, fabsdk.WithUser("User1"), fabsdk.WithOrg(orgName))
//	// Channel client is used to query and execute transactions (Org1 is default org)
//	client, err := channel.New(clientChannelContext)
//	if err != nil {
//		t.Fatalf("Failed to create new channel client: %s", err)
//	}
//
//	go func() {
//		//t.Logf("2sart send invoke Request Succeed: %s", "---------------start---------")
//
//		//var ccEvent *fab.CCEvent
//		eventID := "test([a-zA-Z]+)"
//		reg, notifier, err := client.RegisterChaincodeEvent(ccID, eventID)
//		if err != nil {
//			t.Fatalf("Failed to register cc event: %s", err)
//		}
//		//t.Logf("3sart send invoke Request Succeed: %s", "---------------start---------")
//
//		defer client.UnregisterChaincodeEvent(reg)
//
//		for {
//			select {
//			case _ = <-notifier:
//				//t.Logf("Received CC event: %#v\n", ccEvent)
//				//lockSuccess.Lock()
//				successCount++
//				//lockSuccess.Unlock()
//			case <-time.After(time.Second * 60):
//				t.Fatalf("Did NOT receive CC event for eventId(%s)\n", eventID)
//				return
//			case <-stopCh:
//				//t.Log("Event Routine force closed \n")
//				return
//			}
//		}
//	}()
//
//	for i := 0; i < nprocess; i++ {
//		go func(index int) {
//			//for j:=0;j<100;j++{
//			for {
//				// Move funds
//				select {
//				case <-stopCh:
//					//t.Logf("Tx Routine force closed (%d)\n", i)
//					return
//				default:
//				}
//				//t.Logf("1sart send invoke Request Succeed: %s", "---------------start---------")
//				_, err := client.Execute(channel.Request{ChaincodeID: ccID, Fcn: "invoke", Args: integration.ExampleCCDefaultTxArgs()},
//					channel.WithRetry(retry.DefaultChannelOpts))
//				//t.Logf("End send invoke Request Succeed: %s", res.TransactionID)
//				if err == nil {
//					//lockTotal.Lock()
//					//totalCount++
//					//lockTotal.Unlock()
//				} else {
//					t.Logf("Failed to move funds: %s", err)
//				}
//
//			}
//		}(i)
//	}
//
//	for {
//		currentTime := time.Now().UnixNano()
//		if currentTime-lastTime > int64(pressTime)*1e9 {
//			//t.Logf("time: %#v , concurrency: %#v, test case: invoke, totalcount: %#v ,success count: %#v, sucess rate: %#v ,tps: %#v\n",
//			//	(currentTime-lastTime)/1e9,nprocess,totalCount,successCount,float64(successCount)/float64(totalCount),float64(successCount)/float64(pressTime))
//			t.Logf("time: %#v , concurrency: %#v, test case: invoke ,success count: %#v ,tps: %#v\n",
//				(currentTime-lastTime)/1e9, nprocess, successCount, float64(successCount)/float64(pressTime))
//
//			close(stopCh)
//			time.Sleep(time.Second)
//			return
//		}
//		time.Sleep(time.Millisecond)
//	}
//}

// RunWithoutSetup will execute the same way as Run but without creating a new channel and registering a new CC
func RunWithoutSetup(t *testing.T, configOpt core.ConfigProvider, sdkOpts ...fabsdk.Option) {
	setupAndRun(t, false, configOpt, e2eTest, "invoke", sdkOpts...)
}

type testSDKFunc func(t *testing.T, sdk *fabsdk.FabricSDK, chainCodeKey string)

// setupAndRun enables testing an end-to-end scenario against the supplied SDK options
// the createChannel flag will be used to either create a channel and the example CC or not(ie run the tests with existing ch and CC)
func setupAndRun(t *testing.T, createChannel bool, configOpt core.ConfigProvider, test testSDKFunc, chainCodeKey string, sdkOpts ...fabsdk.Option) {

	//startTime := time.Now().UnixNano()
	if integration.IsLocal() {
		//If it is a local test then add entity mapping to config backend to parse URLs
		configOpt = integration.AddLocalEntityMapping(configOpt)
	}

	sdk, err := fabsdk.New(configOpt, sdkOpts...)
	if err != nil {
		t.Fatalf("Failed to create new SDK: %s", err)
	}
	defer sdk.Close()

	// Delete all private keys from the crypto suite store
	// and users from the user store at the end
	integration.CleanupUserData(t, sdk)
	defer integration.CleanupUserData(t, sdk)

	if createChannel {
		createChannelAndCC(t, sdk)
	}

	test(t, sdk, chainCodeKey)
	//endTime := time.Now().UnixNano()
	//t.Logf("One transaction time: %#v, chainCodeKey: %#v", float64(endTime-startTime)/1e9, chainCodeKey)
}

func e2eTest(t *testing.T, sdk *fabsdk.FabricSDK, chainCodeKey string) {
	//prepare channel client context using client context
	clientChannelContext := sdk.ChannelContext(channelID, fabsdk.WithUser("User1"), fabsdk.WithOrg(orgName))
	// Channel client is used to query and execute transactions (Org1 is default org)
	client, err := channel.New(clientChannelContext)
	if err != nil {
		t.Fatalf("Failed to create new channel client: %s", err)
	}

	//moveFunds(t, client)
	executeCC(t, client, chainCodeKey)

	// Verify move funds transaction result on the same peer where the event came from.
	//verifyFundsIsMoved(t, client, existingValue, ccEvent)
}

func createChannelAndCC(t *testing.T, sdk *fabsdk.FabricSDK) {
	//clientContext allows creation of transactions using the supplied identity as the credential.
	//clientContext := sdk.Context(fabsdk.WithUser(orgAdmin), fabsdk.WithOrg(ordererOrgName))
	//
	//// Resource management client is responsible for managing channels (create/update channel)
	//// Supply user that has privileges to create channel (in this case orderer admin)
	//resMgmtClient, err := resmgmt.New(clientContext)
	//if err != nil {
	//	t.Fatalf("Failed to create channel management client: %s", err)
	//}
	//
	//// Create channel
	//createChannel(t, sdk, resMgmtClient)

	//prepare context
	adminContext := sdk.Context(fabsdk.WithUser(orgAdmin), fabsdk.WithOrg(orgName))

	// Org resource management client
	orgResMgmt, err := resmgmt.New(adminContext)
	if err != nil {
		t.Fatalf("Failed to create new resource management client: %s", err)
	}

	// Org peers join channel
	//if err = orgResMgmt.JoinChannel(channelID, resmgmt.WithRetry(retry.DefaultResMgmtOpts), resmgmt.WithOrdererEndpoint("orderer.example.com")); err != nil {
	//	t.Fatalf("Org peers failed to JoinChannel: %s", err)
	//}

	// Create chaincode package for example cc
	createCC(t, orgResMgmt)
}

func moveFunds(t *testing.T, client *channel.Client) *fab.CCEvent {

	eventID := "test([a-zA-Z]+)"

	// Register chaincode event (pass in channel which receives event details when the event is complete)
	reg, notifier, err := client.RegisterChaincodeEvent(ccID, eventID)
	if err != nil {
		t.Fatalf("Failed to register cc event: %s", err)
	}
	defer client.UnregisterChaincodeEvent(reg)

	// Move funds
	executeCC(t, client, "invoke")

	var ccEvent *fab.CCEvent
	select {
	case ccEvent = <-notifier:
		t.Logf("Received CC event: %#v\n", ccEvent)
	case <-time.After(time.Second * 30):
		t.Fatalf("Did NOT receive CC event for eventId(%s)\n", eventID)
	}

	return ccEvent
}

func verifyFundsIsMoved(t *testing.T, client *channel.Client, value []byte, ccEvent *fab.CCEvent) {

	newValue := queryCC(t, client, ccEvent.SourceURL)
	valueInt, err := strconv.Atoi(string(value))
	if err != nil {
		t.Fatal(err.Error())
	}
	valueAfterInvokeInt, err := strconv.Atoi(string(newValue))
	if err != nil {
		t.Fatal(err.Error())
	}
	if valueInt+1 != valueAfterInvokeInt {
		t.Fatalf("Execute failed. Before: %s, after: %s", value, newValue)
	}
}

func executeCC(t *testing.T, client *channel.Client, chainCodeKey string) {
	//t.Logf("End send invoke Request Succeed: %s", "---------------start---------")
	//t.Logf("Start send invoke Request: %v", client)
	_, err := client.Execute(channel.Request{ChaincodeID: ccID, Fcn: "invoke", Args: append(integration.ExampleCCDefaultTxArgs(), []byte(chainCodeKey))},
		channel.WithRetry(retry.DefaultChannelOpts))
	//t.Logf("End send invoke Request Succeed: %s", res.TransactionID)
	if err != nil {
		t.Logf("Failed to move funds: %s", err)
	}
	//t.Logf("Response move funds: %#v", res)
}

func queryCC(t *testing.T, client *channel.Client, chainCodeKey string, targetEndpoints ...string) []byte {
	response, err := client.Query(channel.Request{ChaincodeID: ccID, Fcn: "invoke", Args: append(integration.ExampleCCDefaultQueryArgs(), []byte(chainCodeKey))},
		channel.WithRetry(retry.DefaultChannelOpts),
		channel.WithTargetEndpoints(targetEndpoints...),
	)
	if err != nil {
		t.Fatalf("Failed to query funds: %s", err)
	}
	t.Logf("Response query funds: %#v", response)
	return response.Payload
}

func createCC(t *testing.T, orgResMgmt *resmgmt.Client) {
	ccPkg, err := packager.NewCCPackage("github.com/press_test_query_cc", integration.GetDeployPath())
	if err != nil {
		t.Fatal(err)
	}
	// Install example cc to org peers
	installCCReq := resmgmt.InstallCCRequest{Name: ccID, Path: "github.com/press_test_query_cc", Version: "0", Package: ccPkg}
	_, err = orgResMgmt.InstallCC(installCCReq, resmgmt.WithRetry(retry.DefaultResMgmtOpts))
	if err != nil {
		t.Fatal(err)
	}
	// Set up chaincode policy
	ccPolicy := cauthdsl.SignedByAnyMember([]string{"Org1MSP"})
	// Org resource manager will instantiate 'example_cc' on channel
	resp, err := orgResMgmt.InstantiateCC(
		channelID,
		//resmgmt.InstantiateCCRequest{Name: ccID, Path: "github.com/press_test_cc", Version: "0", Args: integration.ExampleCCInitArgs(), Policy: ccPolicy},
		resmgmt.InstantiateCCRequest{Name: ccID, Path: "github.com/press_test_query_cc", Version: "0", Policy: ccPolicy},

		resmgmt.WithRetry(retry.DefaultResMgmtOpts),
	)
	require.Nil(t, err, "error should be nil")
	require.NotEmpty(t, resp, "transaction response should be populated")
}

func createChannel(t *testing.T, sdk *fabsdk.FabricSDK, resMgmtClient *resmgmt.Client) {
	mspClient, err := mspclient.New(sdk.Context(), mspclient.WithOrg(orgName))
	if err != nil {
		t.Fatal(err)
	}
	adminIdentity, err := mspClient.GetSigningIdentity(orgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	req := resmgmt.SaveChannelRequest{ChannelID: channelID,
		ChannelConfigPath: integration.GetChannelConfigTxPath(channelID + ".tx"),
		SigningIdentities: []msp.SigningIdentity{adminIdentity}}
	txID, err := resMgmtClient.SaveChannel(req, resmgmt.WithRetry(retry.DefaultResMgmtOpts), resmgmt.WithOrdererEndpoint("orderer.example.com"))
	require.Nil(t, err, "error should be nil")
	require.NotEmpty(t, txID, "transaction ID should be populated")
}
