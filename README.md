# pac

pac is a simple python wrapper for aws-cli commands related to ec2 instances.
Working as a wrapper of aws-cli, it requires a configured and working version of aws-cli to be present on the pc.

In this moment, using pac you can only:
- inspect all ec2 instances for a specific region (by now it is not possible change region from inside pac)
- inspect securyt group for each instance
- add/remove rules from a security group
- stop (shift off) an istance

It is an absolutely work in progress!


```python
from pac impor Pac
pac = Pac(proxy=False)

pac.inspect_instance("instance_name")
```
