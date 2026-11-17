"""联邦活动的收到与作者授权分开。"""
def assess(rows):
    activities=[r for r in rows if r['kind']=='activity']
    pending=[r['id'] for r in activities if not r['payload'].get('actor_verified')]
    return {'publishable':not pending,'reasons':['活动作者未验证:'+x for x in pending],
            'candidate_activity_count':len(activities)}
