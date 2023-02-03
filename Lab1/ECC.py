import os
import timeit

private_key = os.urandom(32).hex() #random number 32 byte to create private key
print('\nPrivate Key: ', private_key)
private_key=int(private_key, 16)
# print('Private Key: ', private_key, '\n')
# N: max of private key
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Prime = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
print("\nN: ", N)
print("\nPrime:", Prime)
# G(Gx, Gy)
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)

def mod_inverse(a, m):
    y1,y2 = 0,1
    hig, low = m, a%m
    while low>1:
        q=hig//low
        while low > 1:
            q=hig//low
            r=hig%low
            y3=y1-y2*q
            y1,y2,low, hig=y2,y3,r,low
        return y2%m
    
def QGdistinguish(g, q): #Q, G phân biệt
    k=((q[1]-g[1])*mod_inverse(q[0]-g[0], Prime))%Prime
    # xq-xq/yq-yg mod (p)do phép chia không có tính đồng dư nên phải nhân với nghịch đảo modulo của yq-yg
    x = (k**2-g[0]-q[0])%Prime
    # k^2 - xg -xq mod (P)
    y = (k*(g[0]-x)-g[1])%Prime
    # k(xg-x)-yg mod (P)
    return (x,y)

def QGCoincide(g):
    k = ((3*g[0]**2)*mod_inverse(2*g[1], Prime))%Prime
    # 3xg^2/2yg # tương tự ta nhân với nghịch đảo mod 2yg
    x = (k**2-2*g[0])%Prime
    # k^2-2x
    y = (k*(g[0]-x)-g[1])%Prime
    return (x,y)

def ECC(G, private_key):
    # Invalid Private key: = 0 or >= N
    if private_key == 0 or private_key >= N: raise Exception("Invalid private key")
    # Convert Private key to binary string
    private_key = '{0:b}'.format(private_key)
    Q=G
    for i in range(1, len(private_key)):
        Q = QGCoincide(Q) # Nếu chuỗi vị trí '0' gọi là hàm trùng nhau
        if private_key[i] == '1': # Nếu chuỗi vị trí '1' gọi hàm phân biệt
            Q = QGdistinguish(Q,G)
        return (Q) 

begin=timeit.default_timer() 
x, y = ECC(G, private_key)
end=timeit.default_timer()
uncompress = '04' + '{:064x}{:064x}'.format(x,y)
print("\nUncompressed public key: ", uncompress) 

if y%2==0:
    compress='02'+'{0:x}'.format(x)
if y%2==1:
    compress='03'+'{0:x}'.format(x)

print('\nCompressed public key: ', compress)
print('\nTotal runtime of ECC: ', end-begin)


