#!/usr/bin/env python3
"""Generate minimal router classifier ONNX fixtures without dependencies."""

from pathlib import Path


def varint(value):
    data = bytearray()
    while value > 0x7F:
        data.append((value & 0x7F) | 0x80)
        value >>= 7
    data.append(value)
    return bytes(data)


def field(number, wire_type, value):
    return varint((number << 3) | wire_type) + value


def integer(number, value):
    return field(number, 0, varint(value))


def message(number, value):
    return field(number, 2, varint(len(value)) + value)


def text(number, value):
    return message(number, value.encode("utf-8"))


def value_info(name):
    dimension = integer(1, 1)
    shape = message(1, dimension)
    tensor_type = integer(1, 1) + message(2, shape)
    return text(1, name) + message(2, message(1, tensor_type))


def model(classes):
    node = text(1, "input") + text(2, "output") + text(4, "Identity")
    graph = message(1, node) + text(2, "router-classifier-fixture")
    graph += message(11, value_info("input")) + message(12, value_info("output"))
    opset = integer(2, 13)
    metadata = text(1, "muniment.router.classes") + text(2, classes)
    return integer(1, 8) + message(7, graph) + message(8, opset) + message(14, metadata)


def main():
    output = Path(__file__).parent
    output.joinpath("contract.onnx").write_bytes(
        model('["route.cloud","route.local","route.proxy"]')
    )
    output.joinpath("reordered.onnx").write_bytes(
        model('["route.local","route.cloud","route.proxy"]')
    )


if __name__ == "__main__":
    main()
