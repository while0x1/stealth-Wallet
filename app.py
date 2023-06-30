from flask import Flask, render_template, request, flash
app = Flask(__name__)

from blockfrost import ApiUrls
from pycardano import *
from staticVars import *
import json
import ast
from token_registry import *
import requests

app.config['SECRET_KEY'] = SECRET_KEY

pyNet = Network.TESTNET


if pyNet == Network.MAINNET:
    BF_PROJ_ID  = BF_MAINNET_KEY
    chain_context = BlockFrostChainContext(project_id=BF_PROJ_ID,base_url=ApiUrls.mainnet.value,)
else:
    BF_PROJ_ID = BF_PREPROD_KEY
    chain_context = BlockFrostChainContext(project_id=BF_PROJ_ID,base_url=ApiUrls.preprod.value,)

def min_lovelace_post_alonzo(output: TransactionOutput, context: ChainContext) -> int:

    constant_overhead = 160
    amt = output.amount
    if amt.coin == 0:
        amt.coin = 1000000
    # Make sure we are using post-alonzo output
    tmp_out = TransactionOutput(output.address,output.amount,output.datum_hash,output.datum,output.script,True,)
    return (constant_overhead + len(tmp_out.to_cbor("bytes"))) * context.protocol_param.coins_per_utxo_byte


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit', methods=('GET', 'POST'))
def submit():
    signedCBOR = request.form.getlist('signedCBOR')[0].strip()
    tx_id = chain_context.submit_tx(signedCBOR)
    print(tx_id)
    return tx_id
    #return render_template('submitted.html')

@app.route('/tx', methods=('GET', 'POST'))
def tx():
    #print(request.form)
    tx_type = request.form.get("tx_type")
    if tx_type == 'tx':
        from_address = Address.from_primitive(request.form.getlist('from_address')[0])
        to_address = Address.from_primitive(request.form.getlist('Address')[0])
        print(request.form)
        sendAda = request.form.getlist('ADA')[0]
        policy = ''

        #print(sendAda)
        #decimals = getDecimals(nftList['policy'],nftList['assethex'])
        flatform = request.form.to_dict(flat=False)
        assetamount = flatform['assetamount'][0]
        if request.form.get("assetlist") != 'Native Assets':
            assetlist = ast.literal_eval(flatform['assetlist'][0])
            assethex = assetlist['assethex']
            policy = assetlist['policy']
            assetname = assetlist['assetname']
        #print(policy)
        if assetamount != '' and assetamount != '0':
            assetamount = int(assetamount)
        #print(assetamount)

        print(from_address,to_address,sendAda)
        builder = TransactionBuilder(chain_context)
        builder.add_input_address(from_address)
        if sendAda != '':
            sendLovelace = int(float(sendAda) * 1000000)
            builder.add_output(TransactionOutput(to_address,sendLovelace))
        #print(sendLovelace)
        if policy != '' and assetamount != '' and assetamount != '0':
            swap_asset = MultiAsset.from_primitive({bytes.fromhex(policy): {bytes.fromhex(assethex): assetamount}})
                #builder.add_output(TransactionOutput(script_address, Value(1500000, swap_asset), datum_hash=datum_hash(datum)))
            min_lovelace = min_lovelace_post_alonzo(TransactionOutput(to_address, Value(1000000, swap_asset)),chain_context)
            builder.add_output(TransactionOutput(to_address, Value(min_lovelace, swap_asset)))

        print(builder)
        raw = builder.build(change_address=from_address)
        tb = builder._build_tx_body()
        unsignedTx = tb.to_cbor()
    elif tx_type == 'stake':
        print('You are Here')
        from_address = Address.from_primitive(request.form.getlist('from_address')[0])
        poolhash = request.form.get('poolhash')
        stake_key = Address(staking_part = from_address.staking_part, network=pyNet)
        stake_credential = StakeCredential(stake_key.staking_part)
        stake_registration = StakeRegistration(stake_credential)
        pool_hash = PoolKeyHash(bytes.fromhex(poolhash))
        stake_delegation = StakeDelegation(stake_credential, pool_keyhash=pool_hash)
        #BuildTx
        builder = TransactionBuilder(chain_context)
        builder.add_input_address(from_address)
        builder.add_output(TransactionOutput(from_address, 10000000))
        utxos = chain_context.utxos(str(from_address))
        for n in utxos:
            if n.output.amount.coin > 5500000 and not n.output.amount.multi_asset:
                selected_utxo = n
        #utxo = transaction.UTxO.from_cbor
        #tx_in = TransactionInput(utxo.input.transaction_id,utxo.input.index)
        #total_lovelace = utxo.output.amount.coin
        #fees = 250000
        #output1 = TransactionOutput(utxo.output.address,total_lovelace - fee)
        #tx_body = TransactionBody(inputs=[tx_in], outputs=[output1], fee=fees,certificates=[stake_registration, stake_delegation])
        #builder.certificates = [stake_registration, stake_delegation]
        print(from_address)
        print(poolhash)
        #builder._estimate_fee = lambda : 220000
        est_fee = builder._estimate_fee()
        builder._estimate_fee = lambda : est_fee + 25000
        print(f'Builderfee before: {est_fee}')
        raw = builder.build(change_address=from_address)
        print(f'Builderfee after: {builder.fee}')
        tb = builder._build_tx_body()
        unsignedTx = tb.to_cbor()
    #unsignedTx = builder.build_and_sign([], change_address=from_address)

    return render_template('sign.html', unsignedTx=unsignedTx)

@app.route('/query', methods=('GET', 'POST'))
def query():
    try:
        if pyNet == Network.MAINNET:
            BF_PROJ_ID  = 'mainnetp51Dyun2ieF4XrdefrHyNOkeTqWEOYpQ'
            chain_context = BlockFrostChainContext(project_id=BF_PROJ_ID,base_url=ApiUrls.mainnet.value,)
            #from_address = Address(payment_vkey.hash(),network=Network.MAINNET)
        else:
            BF_PROJ_ID = 'preprodOmNfl38Tfadb26AGzm4UG3HA1At1ygXI'
            chain_context = BlockFrostChainContext(project_id=BF_PROJ_ID,base_url=ApiUrls.preprod.value,)
            #from_address = Address(payment_vkey.hash(), network=Network.TESTNET)

        if request.method == 'POST':
            address = request.form['address']
            pyaddress = Address.from_primitive(address)
            stake_address = Address(staking_part=pyaddress.staking_part,network=pyNet)
            #email = request.form.get("address")
            print(address)
            utxos = chain_context.utxos(str(address))
            balance = 0
            for n in utxos:
                balance += n.output.amount.coin
            balance = round((balance/1000000),2)
            print(f'Balance: {balance}')
            assetlist = []
            nlist = []

            for u in utxos:
                if u.output.amount.multi_asset:
                    for a in u.output.amount.multi_asset:
                        policy = a.payload.hex()
                        asset = u.output.amount.multi_asset[a]
                        for n in asset:
                            try:
                                assetName = n.payload.decode()
                            except:
                                assetName = n.payload.decode('ascii','replace')
                            assetAmount = asset[n]
                            assetNameHex = str(n)

                            address = str(u.output.address)
                            assetlist.append({'policy':policy,'assethex':assetNameHex,'amount':str(assetAmount),'assetname':assetName})

            for l in assetlist:
                exclude = False
                for c in nlist:
                    if l['policy'] == c['policy'] and l['assethex'] == c['assethex']:
                        exclude = True
                if not exclude:
                    nlist.append(l)
        #flash('Title is required!')

        queryarray = []
        for i in nlist:

            count = 0
            for a in assetlist:
                #asset_name
                if  i['policy'] == a['policy'] and i['assethex'] == a['assethex'] :
                    count += int(a['amount'])
            print(i['assetname'],count)
            i['amount'] = str(count)
            queryarray.append([i['policy'],i['assethex']])

        dob = {'_asset_list': queryarray}

        #for i in range(1,4):
        #    r = requests.post('https://api.koios.rest/api/v0/asset_info',json=dob)
        #    if r.status_code == 200:
        #        print(r.content)
        #        break
        for i in range(1,4):
                r = requests.post("https://api.koios.rest/api/v0/account_info",json={'_stake_addresses': [[str(stake_address)]]})
                if r.status_code == 200:
                        stake_info = json.loads(r.content)
                        break

        if len(stake_info) == 0:
            ticker = 'Unstaked'
        else:
            pool_id = stake_info[0]['delegated_pool']
            ticker = ''

            for i in range(1,4):
                    r = requests.post("https://api.koios.rest/api/v0/pool_info",json={'_pool_bech32_ids': [[pool_id]]})
                    if r.status_code == 200:
                            pool_info = json.loads(r.content)
                            break
            ticker = pool_info[0]['meta_json']['ticker']

        walletinfo = {'balance':balance,'address':address,'ticker':ticker, 'stake_address': str(stake_address), 'assets': nlist}
        return render_template('query.html', walletinfo=walletinfo)
    except Exception as e:
        print(e)
        return 'Error querying address'
