from .bitcoin import Api as BitcoinApi


def bitcoin_scan_chain(
    height=None, base_url=None, username=None, password=None, timeout=None
):
    kwargs = {"username": username, "password": password}
    if timeout:
        kwargs["timeout"] = timeout
    if base_url:
        kwargs["base_url"] = base_url
    api = BitcoinApi(**kwargs)
    if height is None:
        height = api.get_block_count()

    while height >= 0:
        yield api.get_block_by_height(height)
        height -= 1
