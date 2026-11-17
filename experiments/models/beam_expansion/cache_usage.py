"""Raw provider cache counters. No inference from Pi-normalized usage defaults."""
import collections
import json

PATHS = {
    'read': [('cache_read_input_tokens',), ('input_tokens_details','cached_tokens'),
             ('prompt_tokens_details','cached_tokens'), ('prompt_cache_hit_tokens',)],
    'write': [('cache_creation_input_tokens',), ('cache_write_input_tokens',),
              ('input_tokens_details','cache_write_tokens'), ('prompt_tokens_details','cache_write_tokens'),
              ('prompt_cache_write_tokens',)],
}
DEFINITION = ('Raw request.usage and response.usage aliases only. Equal duplicate reports count once. '
              'A counter must be a nonnegative integer (not boolean). Null/absent is missing; '
              'conflicting or invalid supplied values remain unknown. No fallback to message.usage '
              'cacheRead/cacheWrite defaults. cache_*_reported_tokens is an observed subtotal, null '
              'when no counters are reported; cache_*_tokens is null whenever any request is unknown. '
              'Cache read/write are provider counters, not additional universally additive input tokens or an invoice.')


def observe(request, direction):
    sources, invalid = {}, {}
    response = request.get('response')
    response = response if isinstance(response, dict) else {}
    for prefix, usage in [('usage', request.get('usage')), ('response.usage', response.get('usage'))]:
        if usage is None:
            continue
        if not isinstance(usage, dict):
            invalid[prefix] = usage
            continue
        for path in PATHS[direction]:
            current = usage
            for depth, key in enumerate(path):
                if not isinstance(current, dict):
                    if current is not None:
                        invalid[prefix+'.'+'.'.join(path[:depth])] = current
                    break
                if key not in current:
                    break
                current = current[key]
                if depth == len(path)-1:
                    sources[prefix+'.'+'.'.join(path)] = current
    valid = {k:v for k,v in sources.items() if isinstance(v,int) and not isinstance(v,bool) and v >= 0}
    invalid.update({k:v for k,v in sources.items() if v is not None and k not in valid})
    conflict = len(set(valid.values())) > 1
    status = 'conflicting' if conflict else 'invalid' if invalid else 'reported' if valid else 'missing'
    value = next(iter(valid.values())) if status == 'reported' else None
    return {'status':status,'reported_tokens':value,'counter_sources':sources,
            'conflict':conflict,'invalid_sources':invalid,'resolution':'raw_provider_aliases' if value is not None else None}


def accumulate(counter, request):
    out = {}
    for direction in ['read','write']:
        observation = observe(request, direction)
        out[direction] = observation
        prefix = 'cache_'+direction+'_'
        counter[prefix+'requests'] += 1
        counter[prefix+observation['status']+'_requests'] += 1
        value = observation['reported_tokens']
        if value is None:
            counter[prefix+'unknown_requests'] += 1
        else:
            counter[prefix+'reported_tokens'] += value
            counter[prefix+'explicit_zero_requests'] += value == 0
            counter[prefix+'positive_requests'] += value > 0
    return out


def finalize(counter):
    result = dict(counter)
    for direction in ['read','write']:
        prefix = 'cache_'+direction+'_'
        for name in ['requests','reported_requests','unknown_requests','missing_requests',
                     'conflicting_requests','invalid_requests','explicit_zero_requests','positive_requests']:
            result[prefix+name] = counter[prefix+name]
        reported = counter[prefix+'reported_requests']
        result[prefix+'reported_tokens'] = counter[prefix+'reported_tokens'] if reported else None
        result[prefix+'tokens'] = result[prefix+'reported_tokens'] if reported and not counter[prefix+'unknown_requests'] else None
        result[prefix+'complete'] = bool(reported and not counter[prefix+'unknown_requests'])
    return result


def self_test():
    fixtures = [
        ('explicit_zero','read',{'usage':{'cache_read_input_tokens':0}},0,'reported'),
        ('anthropic','read',{'usage':{'cache_read_input_tokens':11}},11,'reported'),
        ('responses','read',{'usage':{'input_tokens_details':{'cached_tokens':12}}},12,'reported'),
        ('chat','read',{'usage':{'prompt_tokens_details':{'cached_tokens':13}}},13,'reported'),
        ('deepseek_alias','read',{'usage':{'prompt_cache_hit_tokens':14}},14,'reported'),
        ('response_only','read',{'response':{'usage':{'prompt_tokens_details':{'cached_tokens':15}}}},15,'reported'),
        ('equal_aliases_once','read',{'usage':{'cache_read_input_tokens':4,'prompt_tokens_details':{'cached_tokens':4}},'response':{'usage':{'prompt_cache_hit_tokens':4}}},4,'reported'),
        ('missing','read',{'usage':{'input_tokens':7}},None,'missing'),
        ('null','read',{'usage':{'prompt_tokens_details':{'cached_tokens':None}}},None,'missing'),
        ('pi_zero_ignored','write',{'message':{'usage':{'cacheRead':0,'cacheWrite':0}}},None,'missing'),
        ('boolean_invalid','read',{'usage':{'cache_read_input_tokens':False}},None,'invalid'),
        ('negative_invalid','write',{'usage':{'cache_creation_input_tokens':-1}},None,'invalid'),
        ('fraction_invalid','read',{'usage':{'prompt_cache_hit_tokens':1.5}},None,'invalid'),
        ('string_invalid','write',{'usage':{'cache_creation_input_tokens':'3'}},None,'invalid'),
        ('nested_container_invalid','read',{'usage':{'prompt_tokens_details':'bad'}},None,'invalid'),
        ('raw_copy_conflict','read',{'usage':{'prompt_cache_hit_tokens':3},'response':{'usage':{'prompt_cache_hit_tokens':4}}},None,'conflicting'),
        ('valid_and_invalid','write',{'usage':{'cache_creation_input_tokens':2,'input_tokens_details':{'cache_write_tokens':False}}},None,'invalid'),
        ('write_anthropic','write',{'usage':{'cache_creation_input_tokens':2}},2,'reported'),
        ('write_responses','write',{'usage':{'input_tokens_details':{'cache_write_tokens':3}}},3,'reported'),
        ('write_chat','write',{'usage':{'prompt_tokens_details':{'cache_write_tokens':4}}},4,'reported'),
        ('write_equal','write',{'usage':{'cache_write_input_tokens':5,'prompt_cache_write_tokens':5}},5,'reported'),
        ('null_alias_valid','read',{'usage':{'cache_read_input_tokens':None,'prompt_cache_hit_tokens':6}},6,'reported'),
    ]
    records = []
    for name, direction, request, value, status in fixtures:
        observed = observe(request,direction)
        assert (observed['reported_tokens'],observed['status']) == (value,status), name
        records.append({'name':name,'observation':observed,'passed':True})
    counter = collections.Counter()
    accumulate(counter,{'usage':{'cache_read_input_tokens':0}})
    accumulate(counter,{'usage':{'prompt_cache_hit_tokens':3},'response':{'usage':{'prompt_cache_hit_tokens':3}}})
    accumulate(counter,{'message':{'usage':{'cacheRead':0,'cacheWrite':0}}})
    result = finalize(counter)
    assert result['cache_read_reported_tokens'] == 3 and result['cache_read_tokens'] is None
    assert result['cache_read_reported_requests'] == 2 and result['cache_read_unknown_requests'] == 1
    assert result['cache_write_reported_tokens'] is None and result['cache_write_tokens'] is None
    assert result['cache_write_unknown_requests'] == 3
    return {'all_assertions_passed':True,'fixtures':records,'aggregation':result,'model_calls':0,'native_calls':0}


if __name__ == '__main__':
    print(json.dumps(self_test(),indent=2))
