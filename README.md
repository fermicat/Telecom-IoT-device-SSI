# Telecom-IoT-device-SSI


In `main.py`, we go through entire supply chain process.
In `./infra/actions.py`, we define several methods: intereaction of users, wallets, and ledger


## design

1. Schema Creation, Credential Definition Creation. 

Distributor (Mobile Network Operator)  with create schema (Telecom Schema) as standard in the entire supply chain. Both Producer (Manufacturer, called pineapple in our demo) and QA team ( is the QA team of the Manufacturer) will together create Credential Definition.

To simplify the reality, in the use case, the Manufacturer is a different entity compare to MNO (although could be the same some times). Also usually you have several distributors in this case GSMA, assumed only one to make it easier.


2. Device Creation

Once the device is created, the corresponding identity (DID Documents) of the device will be created. The device will be treated as an independent thing and receive the credential from Producer. The device shall  shall be assigned the series number from manufacturer.


3. QA Testing

The device will be passed through QA testing. In the demo, assume passing the QA.

After QA pass, manufacturer will offer a Credential Offer for the device. The device shall receive the Credential from manufacturer. (currently, our credential including: manufacturer, sequence_id, bandwidth, QA_status, history = null)


4. Passing device through Distributor

After receiving Credential from Producer and QA Team, the Distributor (Mobile Network Operator) will assigned and MSISDN in DID Documents of device. After that, the device can connect to the internet.



We simply use the DID to mark the ownership and access control. The KYC process and recycling process are not taken into consideration currently. The changing of ownership from manufacturer to operator, and from operator to end user is use the revoke of DID and claim new DID.

Network: The network will be designed with 3 organizations (Distributor, Producer, QA Team) with 3 peers (User, device A, device B) and will form a consensus among themselves. The DID documents and Verkeys will control the transactions being accepted into the network. 

DID and Verkey: DIDs work as the role of trust anchor to the ledger, as we create Steward’s DID. The actions (including owner’s action and manufacturer's action) is written on the ledger, generate new DID/Verkey pairs. After that, Prover uses Credential Offer to create Credential Request. Trust Anchor then uses Prover's Credential Request to issue a Credential. Steward is then responsible of creating other actors like manufacturer (production line), QA team, distributor (mobile operator) and end customer at various stages. For all the actors, the Steward will onboarding actors mentioned above and then grant verinym and a trust anchor role.
