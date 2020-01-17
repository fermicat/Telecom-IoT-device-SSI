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
                                              json.dumps(['manufacturer', 'protocol', 'bandwidth', 'qa_status',
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
    qaqc_result = True  # set it as true in this demo


    logger.info("=============== STEP 4 ===============")
    logger.info("=== Getting IoT Credential Definition  ==")
    logger.info("=============== ====== ===============")
    
    logger.info("------------------------------")
    logger.info("== Device onboarding  ==")
    logger.info("------------------------------")
    # Physically, the device key belogs to pineapple
    # They can internally doing this
    # however, the log is trackable on chain, especially when QA process is complex with multiple steps
    device_wallet_config = json.dumps({"id": " device_wallet"})
    device_wallet_credentials = json.dumps({"key": "device_wallet_key"})
    device_wallet, pineapple_device_key, device_pineapple_did, device_pineapple_key, pineapple_device_connection_response \
         = await onboarding(pool_handle, "Pineapple", pineapple_wallet, pineapple_did, "Device", None, device_wallet_config,
                            device_wallet_credentials)

    logger.info("==============================")
    logger.info("== Getting IoT QA Credential ==")
    logger.info("------------------------------")

    # assume the result is positive
    if qaqc_result == False:
        exit

    logger.info("\"Pineapple\" -> Create \"IoT\" Credential Offer for Device")
    iot_cred_offer_json = \
        await anoncreds.issuer_create_credential_offer(pineapple_wallet, pineapple_iot_cred_def_id)
 
    device_pineapple_verkey = await did.key_for_did(pool_handle, device_wallet, pineapple_device_connection_response['did'])
 
    authcrypted_iot_cred_offer = await crypto.auth_crypt(pineapple_wallet, pineapple_device_key, device_pineapple_verkey, iot_cred_offer_json.encode('utf-8'))
 
    logger.info("\"Pineapple\" -> Send authcrypted \"IoT\" Credential Offer to Device")
    pineapple_device_verkey, authdecrypted_iot_cred_offer_json, authdecrypted_iot_cred_offer = \
        await auth_decrypt(device_wallet, device_pineapple_key, authcrypted_iot_cred_offer)
 
    # Create and store Device Master Secret in Wallet
    device_master_secret_id = await anoncreds.prover_create_master_secret(device_wallet, None)
 
    logger.info("\"Device\" -> Get \"Pineapple IoT\" Credential Definition from Ledger")
    (pineapple_iot_cred_def_id, pineapple_iot_cred_def) = \
        await get_cred_def(pool_handle, device_pineapple_did, authdecrypted_iot_cred_offer['cred_def_id'])
 
    (iot_cred_request_json, iot_cred_request_metadata_json) = \
        await anoncreds.prover_create_credential_req(device_wallet, device_pineapple_did, authdecrypted_iot_cred_offer_json, pineapple_iot_cred_def, device_master_secret_id)
 
    authcrypted_iot_cred_request = await crypto.auth_crypt(device_wallet, device_pineapple_key, pineapple_device_verkey,
                                                                   iot_cred_request_json.encode('utf-8'))
 
    logger.info("\"Device\" -> Send authcrypted \"IoT\" Credential Request to Pineapple")
    # This credential are locally store in device wallet
    device_pineapple_verkey, authdecrypted_iot_cred_request_json, _ = \
        await auth_decrypt(pineapple_wallet, pineapple_device_key, authcrypted_iot_cred_request)
 
    logger.info("\"Pineapple\" -> Create \"IoT\" Credential for Device")
    iot_cred_values = json.dumps({
        "manufacturer": {"raw": "Pineapple", "encoded": "1324543543255425"},
        "protocol": {"raw": "0x0001", "encoded": "5452313678587"},
        "bandwidth": {"raw": "4G/LTE", "encoded": "874341235654"},
        "qa_status": {"raw": "1", "encoded": "2435345265487786"},      # 1 - pass
        "history": {"raw": "null", "encoded": "875685678678623428"},
    })
 
    iot_cred_json, _, _ = \
        await anoncreds.issuer_create_credential(pineapple_wallet, iot_cred_offer_json,
                                                  authdecrypted_iot_cred_request_json,
                                                  iot_cred_values, None, None)
 
    authcrypted_iot_cred_json = await crypto.auth_crypt(pineapple_wallet, pineapple_device_key, device_pineapple_verkey,
                                                                iot_cred_json.encode('utf-8'))
 
    logger.info("\"Pineapple\" -> Send authcrypted \"IoT\" Credential to Device")
    _, authdecrypted_iot_cred_json, _ = \
        await auth_decrypt(device_wallet, device_pineapple_key, authcrypted_iot_cred_json)
 
    await anoncreds.prover_store_credential(device_wallet, None, iot_cred_request_metadata_json,
                                             authdecrypted_iot_cred_json, pineapple_iot_cred_def, None)



    # have credential approving, assign sequence_id
    logger.info("=============== STEP 5 ===============")
    logger.info("=== have credential approving, assign sequence_id  ==")
    logger.info("=============== ====== ===============")

    logger.info("== IoT Cred-Def proving ==")
    logger.info("------------------------------")

    device_wallet, operator_device_key, device_operator_did, device_operator_key, operator_device_connection_response = \
         await onboarding(pool_handle, "Operator", operator_wallet, operator_did, "Device", device_wallet, device_wallet_config,
                          device_wallet_credentials)
 
    logger.info("\"Operator\" -> Create \"Sequence-Assign\" Proof Request")
    sequence_assign_proof_request_json = json.dumps({
         'nonce': '24354442133432431',
         'name': 'Sequence-Assign',
         'version': '0.1',
         'requested_attributes': {
             'attr1_referent': {
                 'name': 'manufacturer'
             },
             'attr2_referent': {
                 'name': 'protocol'
             },
             'attr3_referent': {
                 'name': 'bandwidth',
                 'restrictions': [{'cred_def_id': pineapple_iot_cred_def_id}]
             },
             'attr4_referent': {
                 'name': 'qa_status',
                 'restrictions': [{'cred_def_id': pineapple_iot_cred_def_id}]
             },
             'attr5_referent': {
                 'name': 'history',
                 'restrictions': [{'cred_def_id': pineapple_iot_cred_def_id}]
             }
         },
         'requested_predicates': {
             'predicate1_referent': {
                 'name': 'qa_status',
                 'p_type': '==',
                 'p_value': 1,
                 'restrictions': [{'cred_def_id': pineapple_iot_cred_def_id}]
             }
         }
    })
 
    logger.info("\"Operator\" -> Get key for Device did")
    device_operator_verkey = await did.key_for_did(pool_handle, operator_wallet, operator_device_connection_response['did'])
 
    logger.info("\"Operator\" -> Authcrypt \"Sequence-Assign\" Proof Request for Device")
    authcrypted_sequence_assign_proof_request_json = \
         await crypto.auth_crypt(operator_wallet, operator_device_key, device_operator_verkey,
                                 sequence_assign_proof_request_json.encode('utf-8'))
 
    logger.info("\"Operator\" -> Send authcrypted \"Sequence-Assign\" Proof Request to Device")
 
    logger.info("\"Device\" -> Authdecrypt \"Sequence-Assign\" Proof Request from Operator")
    operator_device_verkey, authdecrypted_sequence_assign_proof_request_json, _ = \
         await auth_decrypt(device_wallet, device_operator_key, authcrypted_sequence_assign_proof_request_json)
 
    logger.info("\"Device\" -> Get credentials for \"Sequence-Assign\" Proof Request")
 
    search_for_sequence_assign_proof_request = \
         await anoncreds.prover_search_credentials_for_proof_req(device_wallet,
                                                                 authdecrypted_sequence_assign_proof_request_json, None)
 
    cred_for_attr1 = await get_credential_for_referent(search_for_sequence_assign_proof_request, 'attr1_referent')
    cred_for_attr2 = await get_credential_for_referent(search_for_sequence_assign_proof_request, 'attr2_referent')
    cred_for_attr3 = await get_credential_for_referent(search_for_sequence_assign_proof_request, 'attr3_referent')
    cred_for_attr4 = await get_credential_for_referent(search_for_sequence_assign_proof_request, 'attr4_referent')
    cred_for_attr5 = await get_credential_for_referent(search_for_sequence_assign_proof_request, 'attr5_referent')
    cred_for_predicate1 = \
        await get_credential_for_referent(search_for_sequence_assign_proof_request, 'predicate1_referent')
 
    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_sequence_assign_proof_request)
 
    creds_for_sequence_assign_proof = {cred_for_attr1['referent']: cred_for_attr1,
                                        cred_for_attr2['referent']: cred_for_attr2,
                                        cred_for_attr3['referent']: cred_for_attr3,
                                        cred_for_attr4['referent']: cred_for_attr4,
                                        cred_for_attr5['referent']: cred_for_attr5,
                                        cred_for_predicate1['referent']: cred_for_predicate1}
 
    schemas_json, cred_defs_json, revoc_states_json = \
        await prover_get_entities_from_ledger(pool_handle, device_pineapple_did, creds_for_sequence_assign_proof, 'Device')
 
    logger.info("\"Device\" -> Create \"Sequence-Assign\" Proof")
    sequence_assign_requested_creds_json = json.dumps({
         'self_attested_attributes': {
             'attr1_referent': 'Device',
         },
         'requested_attributes': {
             'attr3_referent': {'cred_id': cred_for_attr3['referent'], 'revealed': True}
         },
         'requested_predicates': {'predicate1_referent': {'cred_id': cred_for_predicate1['referent']}}
    })
 
    sequence_assign_proof_json = \
         await anoncreds.prover_create_proof(device_wallet, authdecrypted_sequence_assign_proof_request_json,
                                             sequence_assign_requested_creds_json, device_master_secret_id,
                                             schemas_json, cred_defs_json, revoc_states_json)
 
    logger.info("\"Device\" -> Authcrypt \"Sequence-Assign\" Proof for Operator")
    authcrypted_sequence_assign_proof_json = await crypto.auth_crypt(device_wallet, device_operator_key, operator_device_verkey,
                                                                      sequence_assign_proof_json.encode('utf-8'))
 
    logger.info("\"Device\" -> Send authcrypted \"Sequence-Assign\" Proof to Operator")
 
    logger.info("\"Operator\" -> Authdecrypted \"Sequence-Assign\" Proof from Device")
    _, decrypted_sequence_assign_proof_json, decrypted_sequence_assign_proof = \
         await auth_decrypt(operator_wallet, operator_device_key, authcrypted_sequence_assign_proof_json)
 
    schemas_json, cred_defs_json, revoc_ref_defs_json, revoc_regs_json = \
         await verifier_get_entities_from_ledger(pool_handle, operator_did,
                                                 decrypted_sequence_assign_proof['identifiers'], 'Operator')
 
    logger.info("\"Operator\" -> Verify \"Sequence-Assign\" Proof from Device")
    assert '4G/LTE' == \
            decrypted_sequence_assign_proof['requested_proof']['revealed_attrs']['attr3_referent']['raw']
    assert 'Device' == decrypted_sequence_assign_proof['requested_proof']['self_attested_attrs']['attr1_referent']
    
    assert await anoncreds.verifier_verify_proof(sequence_assign_proof_request_json,
                                                  decrypted_sequence_assign_proof_json,
                                                  schemas_json, cred_defs_json, revoc_ref_defs_json, revoc_regs_json)

    # Assigned sequence ID

    # close instance    
    
    await wallet.close_wallet(steward_wallet)
    await wallet.delete_wallet(steward_wallet_config, steward_wallet_credentials)
    
    await wallet.close_wallet(operator_wallet)
    await wallet.delete_wallet(operator_wallet_config, operator_wallet_credentials)
 
    await wallet.close_wallet(pineapple_wallet)
    await wallet.delete_wallet(pineapple_wallet_config, pineapple_wallet_credentials)

    await wallet.close_wallet(device_wallet)
    await wallet.delete_wallet(device_wallet_config, device_wallet_credentials)
 
    await pool.close_pool_ledger(pool_handle)
    await pool.delete_pool_ledger_config(pool_name)
 
    logger.info("done")

if __name__ == '__main__':
    run_coroutine(run)
    time.sleep(1)