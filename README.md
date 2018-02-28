## Description 
Modern URL classification systems can classify most URLs without ever needing URL content. This is
important because it is far less expensive to classify a URL without having to crawl, download, store, and
analyze content. Furthermore, it is often impossible to access content of a URL due to single-shot and
auto-cloaking malicious websites. In this lab I build a rule-based micro-classifier which uses scoring for
different URL features. I will run the classification set through our newly built micro URL classifier and
see what results.

## Installation
```
cas@ubuntu:~/working_dir/url_reputation$ virtualenv -p /home/cas/miniconda/bin/python --no-site-packages env
cas@ubuntu:~/working_dir/url_reputation$ env/bin/activate
(env) cas@ubuntu:~/working_dir/url_reputation$ pip install -r requirements.txt
```
## Use
```
(env) cas@ubuntu:~/working_dir/url_reputation$ python readcorpus.py --file train.json
Total URLs Analyzed: 2006
Total Malicious URLs detected: 935
Results Saved at: train_out.csv
(env) cas@ubuntu:~/working_dir/url_reputation$ python readcorpus.py --file classify.json
Total URLs Analyzed: 2024
Total Malicious URLs detected: 1008
Results Saved at: classify_out.csv
(env) cas@ubuntu:~/working_dir/url_rep
```
