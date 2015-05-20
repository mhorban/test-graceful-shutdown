#!/usr/bin/env python

import unittest
from multiprocessing import Pool
from optparse import OptionParser
import os
import sys
import subprocess
import threading
import time
import urllib
import urllib2
import json


def get_flavor_list(args):
	get_flavor_list_url, ip_address, os_api_port, token_id, tenant_id = args
	response = None
	try:
		req = urllib2.Request(get_flavor_list_url.format(
			ip_address, os_api_port, tenant_id))
		req.add_header("Content-Type", "application/json")
		req.add_header("X-Auth-Token", str(token_id))
		response = urllib2.urlopen(req, None)
	except:
		return str(sys.exc_info())
	finally:
		if response:
			response.close()


class TestGracefulShutdown(unittest.TestCase):

	def setUp(self):
		parser = OptionParser(usage="usage: %prog [options] tenant-name user password ip-address")
		parser.add_option("-k", "--keystone-port", dest="keystone_port",
			help="keystone port", type="int", default=5000)
		parser.add_option("-a", "--os-api-compute-port", dest="os_api_compute_port",
			help="openstack api compute port", type="int", default=8774)
		parser.add_option("-t", "--threads", dest="threads",
			help="threads count", type="int", default=10)
		parser.add_option("-r", "--requests", dest="requests",
			help="requests count", type="int", default=500)
		(options, args) = parser.parse_args()
		self.tenant_name, self.user, self.password, self.ip_address = args
		self.keystone_port = options.keystone_port
		self.os_api_compute_port = options.os_api_compute_port
		self.requests = options.requests

		# get pid of parent nova-api process
		proc = subprocess.Popen(["ps xao pid,ppid,command | grep nova-api | "
			"grep -v grep | awk '{print $1 \" \" $2'}"],
			stdout=subprocess.PIPE, shell=True)
		(out, err) = proc.communicate()
		pairs = zip(out.split()[::2], out.split()[1::2])
		ppid_found = False
		for child_pair in pairs:
			for parent_pair in pairs:
				if child_pair[1] == parent_pair[0]:
					self.nova_api_ppid = parent_pair[0]
					ppid_found = True
					break
			if ppid_found:
				break
		self.assertTrue(ppid_found)

		# get token and project ID
		self.auth_body = '{{"auth": {{"tenantName": "{0}", "passwordCredentials": {{"username": "{1}", "password": "{2}"}}}}}}'
		url = "http://{0}:{1}/v2.0/tokens".format(self.ip_address, self.keystone_port)
		req = urllib2.Request(url)
		req.add_header("Content-Type", "application/json")
		data = self.auth_body.format(self.tenant_name, self.user, self.password)
		try:
			response = urllib2.urlopen(req, data)
		except urllib2.URLError as error:
			print error
			sys.exit()
		access = json.loads(response.read())
		self.token_id = access['access']['token']['id']
		self.tenant_id = access['access']['token']['tenant']['id']
		response.close()

		self.get_flavor_list_url = "http://{0}:{1}/v2/{2}/flavors"
		self.exception_in_thread = False
		self.thread_pool = Pool(processes=options.threads)

	def spawn_threads(self):
		self.flavor_list_result = self.thread_pool.map(
			get_flavor_list, [(self.get_flavor_list_url,
			self.ip_address, self.os_api_compute_port, self.token_id, self.tenant_id)] * self.requests)

	def test_shutdown(self):
		start_get_flavor_threads = threading.Thread(target=self.spawn_threads)
		start_get_flavor_threads.start()
		time.sleep(3)
		subprocess.Popen(["kill -term %s" % self.nova_api_ppid], shell=True)
		print "KILLED"

		start_get_flavor_threads.join()

		errors = 0
		for res in self.flavor_list_result:
			if (res != None) and ('Connection refused' not in str(res)):
				print str(res)
				errors += 1
			else:
				print 'OK', str(res)

		print 'Errors', errors

		for res in self.flavor_list_result:
			self.assertFalse((res != None) and ('Connection refused' not in str(res)))


if __name__ == "__main__":
	suite = unittest.TestSuite()
	suite.addTest(TestGracefulShutdown("test_shutdown"))
	unittest.TextTestRunner().run(suite)

