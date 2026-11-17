import json
def decode(raw, manifest):
    doc=json.loads(raw.decode('utf-8'))
    records=[]
    for item in doc['orderedItems']:
        if item.get('type') not in ('Create','Update','Delete','Announce','Undo'):raise ValueError('活动类型非法')
        actor=item['actor'];obj=item['object'];object_id=obj['id'] if isinstance(obj,dict) else obj
        if not any(x['id']==actor for x in records):
            records.append({'kind':'actor','id':actor,'version':'received','refs':[],
                            'payload':{'source_url':manifest['source_url']}})
        if isinstance(obj,dict):
            records.append({'kind':'object','id':object_id,'version':'received','refs':[actor],
                            'payload':{'type':obj['type'],'content':obj.get('content')}})
        records.append({'kind':'activity','id':item['id'],'version':'received','refs':[actor,object_id],
                        'payload':{'type':item['type'],'actor':actor,'object':object_id}})
    return {'protocol':manifest['protocol'],'collection':manifest['collection'],'records':records}
