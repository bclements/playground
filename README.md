# Python Playground

## MacOS/Linux Deployment
export VT_APIKEY=<apikey>
git clone https://github.com/bclements/playground.git
cd playground
virtualenv -p /usr/bin/python2.7 .
pip install --requirement requirements.txt
source bin/activate
python main.py 192.168.1.1
python main.py yahoo.com

