package globals

import (
	"time"
)

type ConfigType string

const (
	ConfigTypeActive    ConfigType = "active"
	ConfigTypeCandidate ConfigType = "candidate"
	// ========= Changeset Defaults =========
	PermissionLessExecutionThreshold        = 8 * time.Hour
	RemoteGasPriceBatchWriteFrequency       = 30 * time.Minute
	TokenPriceBatchWriteFrequency           = 30 * time.Minute
	BatchGasLimit                           = 6_500_000
	InflightCacheExpiry                     = 10 * time.Minute
	RootSnoozeTime                          = 30 * time.Minute
	BatchingStrategyID                      = 0
	DeltaProgress                           = 10 * time.Second
	DeltaResend                             = 10 * time.Second
	DeltaInitial                            = 20 * time.Second
	DeltaRound                              = 2 * time.Second
	DeltaGrace                              = 2 * time.Second
	DeltaCertifiedCommitRequest             = 10 * time.Second
	DeltaStage                              = 10 * time.Second
	Rmax                                    = 50
	MaxDurationQuery                        = 500 * time.Millisecond
	MaxDurationObservation                  = 5 * time.Second
	MaxDurationShouldAcceptAttestedReport   = 10 * time.Second
	MaxDurationShouldTransmitAcceptedReport = 10 * time.Second
	GasPriceDeviationPPB                    = 1000
	DAGasPriceDeviationPPB                  = 0
	OptimisticConfirmations                 = 1
	// ======================================

	// ========= Onchain consts =========
	// CCIPLockOrBurnV1RetBytes Pool.CCIP_LOCK_OR_BURN_V1_RET_BYTES
	// Reference: https://github.com/smartcontractkit/chainlink/blob/develop/contracts/src/v0.8/ccip/libraries/Pool.sol#L17
	CCIPLockOrBurnV1RetBytes = 32
	// ======================================
)
