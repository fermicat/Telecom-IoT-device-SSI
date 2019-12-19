import time

from indy import anoncreds, crypto, did, ledger, pool, wallet

import json
import logging
from typing import Optional

from indy.error import ErrorCode, IndyError

from infra.utils import get_pool_genesis_txn_path, run_coroutine, PROTOCOL_VERSION
from infra.actions import *


async def run():
    """
    """

    # Initial pool
    pool_name = 'pool1'
    logger.info("Open Pool Ledger: {}".format(pool_name))
    pool_genesis_txn_path = get_pool_genesis_txn_path(pool_name)
    pool_config = json.dumps({"genesis_txn": str(pool_genesis_txn_path)})
    print(pool_config)

    await pool.set_protocol_version(PROTOCOL_VERSION)
 
    try:
        await pool.create_pool_ledger_config(pool_name, pool_config)
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass
    pool_handle = await pool.open_pool_ledger(pool_name, None)

    # set up the Master (Steward)
    logger.info("\"Steward\" -> Create wallet")
    steward_wallet_config = json.dumps({"id": "steward_wallet"})
    steward_wallet_credentials = json.dumps({"key": "steward_wallet_key"})
    try:
        await wallet.create_wallet(steward_wallet_config, steward_wallet_credentials)
    except IndyError as ex:
        if ex.error_code == ErrorCode.WalletAlreadyExistsError:
            pass
 
    steward_wallet = await wallet.open_wallet(steward_wallet_config, steward_wallet_credentials)
 
    logger.info("\"Steward\" -> Create and store in Wallet DID from seed")
    steward_did_info = {'seed': '000000000000000000000000Steward1'}
    (steward_did, steward_key) = await did.create_and_store_my_did(steward_wallet, json.dumps(steward_did_info))


    # Onboarding Trust Anchor, getting Verinym for them
    logger.info("=============== STEP 0 ===============")
    logger.info("=== Getting Trust Anchor credentials for Network Operator, Manufacturer, QA team  ==")
    logger.info("=============== ====== ===============")

    logger.info("------------------------------")
    logger.info("== Getting Trust Anchor credentials - Network Operator  ==")
    logger.info("------------------------------")
    operator_wallet_config = json.dumps({"id": "operator_wallet"})
    operator_wallet_credentials = json.dumps({"key": "operator_wallet_key"})
    operator_wallet, steward_operator_key, operator_steward_did, operator_steward_key, _ \
        = await onboarding(pool_handle, "Steward", steward_wallet, steward_did, "operator", None,
                            operator_wallet_config, operator_wallet_credentials)

    logger.info("--------- get verinym ---------------")
    operator_did = await get_verinym(pool_handle, "Steward", steward_wallet, steward_did,
                                        steward_operator_key, "Operator", operator_wallet, operator_steward_did,
                                        operator_steward_key, 'TRUST_ANCHOR')

    logger.info("------------------------------")
    logger.info("== Getting Trust Anchor credentials - Manufacturer (pineapple)  ==")
    logger.info("------------------------------")
    pineapple_wallet_config = json.dumps({"id": "pineapple_wallet"})
    pineapple_wallet_credentials = json.dumps({"key": "pineapple_wallet_key"})
    pineapple_wallet, steward_pineapple_key, pineapple_steward_did, pineapple_steward_key, _ = \
         await onboarding(pool_handle, "Steward", steward_wallet, steward_did, "Pineapple", None, pineapple_wallet_config,
                          pineapple_wallet_credentials)
 
    logger.info("--------- get verinym ---------------")
    pineapple_did = await get_verinym(pool_handle, "Steward", steward_wallet, steward_did, steward_pineapple_key,
                                   "Pineapple", pineapple_wallet, pineapple_steward_did, pineapple_steward_key, 'TRUST_ANCHOR')

    logger.info("------------------------------")
    logger.info("== Getting Trust Anchor credentials - QA Team  ==")
    logger.info("------------------------------")
 
    qateam_wallet_config = json.dumps({"id": "qateam_wallet"})
    qateam_wallet_credentials = json.dumps({"key": "qateam_wallet_key"})
    qateam_wallet, steward_qateam_key, qateam_steward_did, qateam_steward_key, _ = \
        await onboarding(pool_handle, "Steward", steward_wallet, steward_did, "Qateam", None, qateam_wallet_config,
                          qateam_wallet_credentials)
 
     
    logger.info("--------- get verinym ---------------")
    qateam_did = await get_verinym(pool_handle, "Steward", steward_wallet, steward_did, steward_qateam_key,
                                  "Qateam",qateam_wallet, qateam_steward_did, qateam_steward_key, 'TRUST_ANCHOR')


    # Network Operator issue Telecom Schema
    logger.info("=============== STEP 1 ===============")
    logger.info("=== Network Operator issue Telecom Schema  ==")
    logger.info("=============== ====== ===============")
    logger.info("\"Operator\" -> Create \"Telecom\" Schema")
    (telecom_schema_id, telecom_schema) = \
         await anoncreds.issuer_create_schema(operator_did, 'Telecom', '0.2',
                                              json.dumps(['manufacturer', 'sequence_id', 'bandwidth', 'qa_status',
                                                          'history'])) # sample schema
 
    logger.info("\"Operator\" -> Send \"Telecom\" Schema to Ledger")
    await send_schema(pool_handle, operator_wallet, operator_did, telecom_schema)
 
    time.sleep(1)  # sleep 1 second before getting schema


    logger.info("=============== STEP 2 ===============")
    logger.info("=== Pineapple issue IoT Credential Definition  ==")
    logger.info("=============== ====== ===============")
 
    logger.info("\"Pineapple\" -> Get \"Telecom\" Schema from Ledger")
    (_, telecom_schema) = await get_schema(pool_handle, pineapple_did, telecom_schema_id)
 
    logger.info("\"Pineapple\" -> Create and store in Wallet \"Pineapple IoT\" Credential Definition")
    (pineapple_iot_cred_def_id, pineapple_iot_cred_def_json) = \
        await anoncreds.issuer_create_and_store_credential_def(pineapple_wallet, pineapple_did, telecom_schema,
                                                                'TAG1', 'CL', '{"support_revocation": false}')
 
    logger.info("\"Pineapple\" -> Send  \"Pineapple IoT\" Credential Definition to Ledger")
    await send_cred_def(pool_handle, pineapple_wallet, pineapple_did, pineapple_iot_cred_def_json)

    logger.info("=============== STEP 3 ===============")
    logger.info("=== QA team do the physical exam  ==")
    logger.info("=============== ====== ===============")
    # This step involve actual physical operations
    qaqc_result = True  # set it as true in this demostration


    logger.info("=============== STEP 4 ===============")
    logger.info("=== Getting IoT Credential Definition  ==")
    logger.info("=============== ====== ===============")
    
    logger.info("------------------------------")
    logger.info("== Device onboarding  ==")
    logger.info("------------------------------")
    device_wallet_config = json.dumps({"id": " device_wallet"})
    device_wallet_credentials = json.dumps({"key": "device_wallet_key"})
    device_wallet, pineapple_device_key, device_pineapple_did, device_pineapple_key, pineapple_device_connection_response \
         = await onboarding(pool_handle, "Pineapple", pineapple_wallet, pineapple_did, "Device", None, device_wallet_config,
                            device_wallet_credentials)

    logger.info("==============================")
    logger.info("== Getting IoT QA Credential ==")
    logger.info("------------------------------")

    if qaqc_result == True:
        """
        """






if __name__ == '__main__':
    run_coroutine(run)
    time.sleep(1)