import json

if __name__ == '__main__':
    dic = {"aaa":"ccc"}
    dic2 = json.dumps(dic)
    print(type(dic2))
    print(dic2)
    print(dic)