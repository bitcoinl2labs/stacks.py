import json


def hex_to_bytes(hex_data):
    return b"".join(
        [bytes((int(hex_data[i : i + 2], 16),)) for i in range(0, len(hex_data), 2)]
    )


def hex_to_bytes_reversed(hex_data):
    return b"".join(
        reversed(
            [bytes((int(hex_data[i : i + 2], 16),)) for i in range(0, len(hex_data), 2)]
        )
    )


def bytes_to_hex(data):
    return "".join(format(x, "02x") for x in data)


def bytes_to_hex_reversed(data):
    return bytes_to_hex(reversed(data))


class JSON:

    def to_json(self):
        return json.dumps(self.to_dict())
