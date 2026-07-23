def build_replay_message(request_id: str,  message_id: str, context_id: str, text: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "SendMessage",
        "params": {
            "message": {
                "messageId": message_id,
                "contextId": context_id,
                "role": "ROLE_USER",
                "parts": [
                    {
                        "text": text,
                        "mediaType": "text/plain"
                    }
                ]
            },
            "configuration": {
                "acceptedOutputModes": ["text/plain"]
            }
        }
    }
