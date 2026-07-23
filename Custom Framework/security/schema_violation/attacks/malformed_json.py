#this closing brace is intentionally missing
def build_payload(request_id: str) -> str:
    return f'{{"jsonrpc":"2.0","id":"{request_id}","method":"SendMessage"'
