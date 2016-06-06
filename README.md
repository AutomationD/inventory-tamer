# Inventory Tamer 

## What is it?
Inventory Tamer is a command line utility that solves the following issues in your network:
- Untracked hosts (is there a host?)
- Stale static IP Address list (is this IP used?) 

## How does it work?
The power of Nmap is used to scan a given range

## Quickstart
### Install package
```
pip install git+https://github.com/kireevco/inventory-tamer
```

### Create a working directory
```
mkdir -p ~/inventory && cd ~/inventory
```

### Initialize Tamer
```
it init
```


### Configure Test Credentials
_Add your ssh username/password to credentials.yml_

### Run Scan
```
sudo it scan -t 192.168.1.1/24
```

### Run Default Report
_Use the subnet that you ran scan for_
```
it report -t 192.168.1.1/24
```

### Run VmWare CSV Report
_Use the subnet that you ran scan for_
```
it report --name csv-vmware -t 192.168.1.1/24
```

### Run VmWare Markdown Report
_Use the subnet that you ran scan for_
```
it report --name md-vmware -t 192.168.1.1/24
```




