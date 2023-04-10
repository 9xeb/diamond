def ioc_cache(func):
    #def inner(*args, **kwargs):
    def inner(ioc, cache):
        if len(cache) > 128:
            cache.pop(0)
        if ioc not in cache:
            func(ioc)
            cache.append(ioc)
        

def compare_ioc( ioc, iocs_list, key):
    def compare_ioc_aux(iocs, ioc, inf, sup):
        if inf > sup:
            return -1
        mid=int((inf+sup)/2)
        if ioc > iocs[mid][key]:
            return compare_ioc_aux(iocs, ioc, mid+1, sup)
        elif ioc < iocs[mid][key]:
            return compare_ioc_aux(iocs, ioc, inf, mid-1)
        else:
            return mid
    return compare_ioc_aux(iocs_list, ioc, 0, len(iocs_list))