import urllib.request
import json

def test_vault():
    # 1. Get Cases
    cases = json.loads(urllib.request.urlopen('http://127.0.0.1:8000/api/v1/investigation/cases').read().decode())
    print(f"[*] Found {len(cases)} cases")
    cid = cases[0]['case_id']

    # 2. Get Events
    events = json.loads(urllib.request.urlopen('http://127.0.0.1:8000/api/v1/telemetry/events').read().decode())
    print(f"[*] Found {len(events)} events")
    eids = [e['event_id'] for e in events[:3]]

    # 3. Acquire into Vault
    req_data = json.dumps({
        'case_id': cid,
        'source_key': 'ssh_auth',
        'source_title': 'SSH Auth Logs',
        'event_ids': eids
    }).encode()
    req = urllib.request.Request('http://127.0.0.1:8000/api/v1/vault/acquire', data=req_data, headers={'Content-Type': 'application/json'})
    res = json.loads(urllib.request.urlopen(req).read().decode())
    print(f"[+] Preserved in Vault: {res['evidence_id']}")
    print(f"    SHA-256 Hash: {res['sha256_hash']}")
    print(f"    Status: {res['integrity_status']}")

    # 4. Verify Integrity
    v_req = urllib.request.Request(f'http://127.0.0.1:8000/api/v1/vault/verify/{res["evidence_id"]}', data=b'', headers={'Content-Type': 'application/json'}, method='POST')
    v_res = json.loads(urllib.request.urlopen(v_req).read().decode())
    print(f"[+] Verification Result: {v_res['status']}")
    print(f"    Verified: {v_res['verified']}")
    print(f"    Calculated SHA-256: {v_res['calculated_sha256']}")
    print(f"    Expected SHA-256:   {v_res['expected_sha256']}")

if __name__ == '__main__':
    test_vault()
