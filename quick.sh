echo "pass"
curl https://www.google.com > $$; rm $$;

echo "drop"
ping www.google.com

echo "drop"
ping www.ibearhost.com

echo "drop"
curl http://www.ibearhost.com > $$; rm $$;

echo "pass"
#traceroute www.ibearhost.com

echo "pass"
ping www.amazon.cn

echo "pass"
ssh cs168-du@hive8.cs.berkeley.edu

echo "pass"
#traceroute www.berkeley.edu

echo "pass: ssh cs168-du@star.cs.berkeley.edu"
ssh cs168-du@star.cs.berkeley.edu

echo "pass"
ping www.taobao.com

echo "drop ping www.stanford.edu"
ping www.stanford.edu

echo "drop dig www.deanza.edu"
dig www.deanza.edu
