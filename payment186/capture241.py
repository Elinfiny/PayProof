"""Validate capture POST evidence separately from the full order GET.

Never synthesize omitted order amount/timestamps. The subsequent full order
GET and authenticated webhook remain mandatory for verified completion.
"""
from datetime import datetime
from .common import require,re

def completed_capture241(raw,expected,not_before,now):
    require(type(raw) is dict and raw.get('id')==expected['id'] and raw.get('status')=='COMPLETED','CAPTURE_ORDER241')
    units=raw.get('purchase_units')
    require(type(units) is list and len(units)==1 and type(units[0]) is dict,'CAPTURE_UNIT241')
    unit=units[0];payments=unit.get('payments')
    require(type(payments) is dict and all(k=='captures' or v==[] for k,v in payments.items()),'CAPTURE_COLLECTION241')
    captures=payments.get('captures')
    require(type(captures) is list and len(captures)==1 and type(captures[0]) is dict,'CAPTURE_COLLECTION241')
    capture=captures[0];cid=capture.get('id');amount=capture.get('amount')
    require(type(cid) is str and re.fullmatch('[A-Z0-9-]{1,64}',cid) and capture.get('status')=='COMPLETED' and capture.get('final_capture') is True,'CAPTURE_ID_STATUS241')
    require(type(amount) is dict and (amount.get('value'),amount.get('currency_code'))==(expected['amount'],expected['currency']),'CAPTURE_AMOUNT241')
    if 'amount' in unit:
        a=unit['amount'];require(type(a) is dict and (a.get('value'),a.get('currency_code'))==(expected['amount'],expected['currency']),'CAPTURE_UNIT_AMOUNT241')
    def stamp(value):
        require(type(value) is str,'CAPTURE_TIME241')
        try:t=datetime.fromisoformat(value.replace('Z','+00:00'))
        except ValueError:require(False,'CAPTURE_TIME241')
        require(t.tzinfo is not None and not_before<=t.timestamp()<=now,'CAPTURE_TIME241')
        return t.timestamp()
    created=stamp(capture.get('create_time'));updated=stamp(capture.get('update_time'))
    require(created<=updated,'CAPTURE_TIME241')
    if 'update_time' in raw:stamp(raw['update_time'])
    return cid
