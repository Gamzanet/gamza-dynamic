import json
from web3 import Web3

# calldata = (
#     w3.keccak(text="upgradeToAndCall(address,bytes)")[:4] +
#     w3.codec.encode(['address', 'bytes'], [proxy_address, bytes(1)])
# )

w3 = Web3()
json_inputs = json.load(open("./input.json"))["inputs"]

def generate_calldata(inputs):
    types, values = [], []
    for item in inputs:
        for key, value in item.items():
            if isinstance(value, list):
                sub_types, sub_values = generate_calldata(value)
                types.extend(sub_types)
                values.extend(sub_values)
            else:
                types.append(key)
                values.append(value)
    return types, values

types, values = generate_calldata(json_inputs)
calldata = w3.codec.encode(types, values)
print(calldata.hex())