package account

import (
	"bytes"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/lnwallet/chanfunding"
)

// selectInputs selects a slice of inputs necessary to meet the specified
// selection amount. If input selection is unable to succeed due to insufficient
// funds, a non-nil error is returned. Additionally, the total amount of the
// selected coins are returned in order for the caller to properly handle
// change+fees.
func selectInputs(amt btcutil.Amount, coins []chanfunding.Coin,
	lndUtxoAddress []byte) (btcutil.Amount, []chanfunding.Coin, error) {

	var selectedCoins []chanfunding.Coin

	satSelected := btcutil.Amount(0)
	for _, coin := range coins {
		if lndUtxoAddress != nil {
			decodedPkScriptAddress, err := decodePkScriptToAddress(coin.PkScript)
			if err != nil {
				// TODO: do something with this error
				continue
			}

			if !bytes.Equal(decodedPkScriptAddress, lndUtxoAddress) {
				continue
			}
		}
		satSelected += btcutil.Amount(coin.Value)
		selectedCoins = append(selectedCoins, coin)

		if satSelected >= amt {
			return satSelected, selectedCoins, nil
		}
	}

	return 0, nil, fmt.Errorf("insufficient funds: need %v, have %v",
		amt, satSelected)
}

// coinSelection attempts to select a sufficient amount of coins, including a
// change output to fund amt satoshis, adhering to the specified fee rate. The
// specified fee rate should be expressed in sat/kw for coin selection to
// function properly.
//
// TODO(wilmer): Replace this with a variant in lnd that allows us to specify
// the base inputs and outputs, rather than assuming we're funding a channel.
func coinSelection(coins []chanfunding.Coin, amt btcutil.Amount,
	witnessType witnessType, feeRate chainfee.SatPerKWeight, lndUtxoAddress []byte) (
	[]chanfunding.Coin, btcutil.Amount, error) {

	amtNeeded := amt
	for {
		// First perform an initial round of coin selection to estimate
		// the required fee.
		totalSat, selectedUtxos, err := selectInputs(amtNeeded, coins, lndUtxoAddress)
		if err != nil {
			return nil, 0, err
		}

		// Add the base account modification weight. This already
		// includes the re-created account output, so we don't need to
		// add it later on.
		var weightEstimator input.TxWeightEstimator
		err = addBaseAccountModificationWeight(
			&weightEstimator, witnessType,
		)
		if err != nil {
			return nil, 0, err
		}

		// Add the proper weights for all of the selections UTXOs.
		for _, utxo := range selectedUtxos {
			switch {
			case txscript.IsPayToWitnessPubKeyHash(utxo.PkScript):
				weightEstimator.AddP2WKHInput()
			case txscript.IsPayToScriptHash(utxo.PkScript):
				weightEstimator.AddNestedP2WKHInput()
			default:
				return nil, 0, fmt.Errorf("unsupported "+
					"address type: %x", utxo.PkScript)
			}
		}

		// The change output is always P2WKH.
		weightEstimator.AddP2WKHOutput()

		// The difference between the selected amount and the amount
		// requested will be used to pay fees, and generate a change
		// output with the remaining.
		overShootAmt := totalSat - amt

		// Based on the estimated size and fee rate, if the excess
		// amount isn't enough to pay fees, then increase the requested
		// coin amount by the estimate required fee, performing another
		// round of coin selection.
		totalWeight := int64(weightEstimator.Weight())
		requiredFee := feeRate.FeeForWeight(totalWeight)
		if overShootAmt < requiredFee {
			amtNeeded = amt + requiredFee
			continue
		}

		// If the fee is sufficient, then calculate the size of the
		// change output.
		changeAmt := overShootAmt - requiredFee

		return selectedUtxos, changeAmt, nil
	}
}

func decodePkScriptToAddress(pkScript []byte) ([]byte, error) {
	_, addresses, _, err := txscript.ExtractPkScriptAddrs(pkScript, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("unable to decode public key script: %v", err)
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("no addresses decoded from pkScript %x", pkScript)
	}

	return addresses[0].ScriptAddress(), nil
}
