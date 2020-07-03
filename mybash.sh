go build -o certutil
./certutil --host www.example.com.ua,127.0.0.1 --ecdsa P256 --o Test --cn CA --cert-fn ca.crt --key-fn ca.key --ca --der
./certutil --host www.example.com.ua,127.0.0.1 --ecdsa P256 --o Test  --parent-cert-fn ca.crt --parent-key-fn ca.key --cert-fn server_crt.pem --key-fn server_key.pem --cn www.example.com.ua --server
./certutil --host www.example.com.ua,127.0.0.1 --ecdsa P256 --o Test  --parent-cert-fn ca.crt --parent-key-fn ca.key --cert-fn client_crt.pem --key-fn client_key.pem --cn www.example.com.ua --client
./certutil --cert-fn ca.crt --key-fn ca.key --der-to-pem 
mv ./ca.crt.pem ./ca_crt.pem
mv ./ca.key.pem ./ca_key.pem
rm ./ca.crt
rm ./ca.key