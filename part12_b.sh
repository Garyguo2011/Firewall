echo 'instant fail >>> curl www.google.com'
curl www.google.com 
echo '*************************************'
echo '*************************************'
echo '*************************************'

echo 'cat pic >>> curl www.deanza.edu'
curl www.deanza.edu
echo '*************************************'
echo '*************************************'
echo '*************************************'

echo 'work properly >>> curl www.yahoo.com'
curl www.yahoo.com > $$; rm $$;
echo '*************************************'
echo '*************************************'
echo '*************************************'

echo 'cat pic >>> curl www.berkeley.edu'
curl www.berkeley.edu
echo '*************************************'
echo '*************************************'
echo '*************************************'

echo 'instant fail >>> curl www.baidu.com'
curl www.baidu.com
echo '*************************************'
echo '*************************************'
echo '*************************************'

echo 'instant fail >>> ssh cs168-ef@star.cs.berkeley.edu'
ssh cs168-ef@star.cs.berkeley.edu
echo '*************************************'
echo '*************************************'
echo '*************************************'

echo 'work properly >>> curl www.amazon.co.uk'
curl www.amazon.co.uk > $$; rm $$;
echo '*************************************'
echo '*************************************'
echo '*************************************'

echo 'instant fail >>> curl www.amazon.cn'
curl www.amazon.cn
echo '*************************************'
echo '*************************************'
echo '*************************************'

echo 'cat pic >>> curl www.dmv.ca.gov'
curl www.dmv.ca.gov