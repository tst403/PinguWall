#!/usr/bin/python3

import unittest
import TransportationTracker as tt

class TestTransportationTrackerMethods(unittest.TestCase):

	def assertDuplex(self, track, ep, port):
		extPort = track.translateOut(ep)
		self.assertEqual(extPort, port)

		intEndpoint = track.translateIn(extPort)
		self.assertEqual(intEndpoint, ep)

	def test_translateOut(self):
			track = tt.TransportationTracker()
			ep = tt.endpoint('192.168.1.1', 1234)
			p1 = track.translateOut(ep)
			p2 = track.translateOut(ep)

			self.assertEqual(p1, p2)

	def test_translateIn(self):
			track = tt.TransportationTracker()
			ep = tt.endpoint('192.168.1.1', 1234)
			p = track.translateOut(ep)

			for x in range(5):
				track.translateOut(ep)

			res1 = track.translateIn(p)
			res2 = track.translateIn(p)

			self.assertEqual(res1, res2)
			self.assertEqual(res1, ep)

	def test_terminateByEndpoint(self):
			track = tt.TransportationTracker()
			ep = tt.endpoint('192.168.1.1', 1234)
			p = track.translateOut(ep)
			track.translateOut(ep)
			track.translateOut(ep)

			track.terminate(tt.endpoint('192.168.1.1', 1234))
			self.assertEqual(track.isEmpty(), True)


	def test_terminateByExtPort(self):
			track = tt.TransportationTracker()
			ep = tt.endpoint('192.168.1.1', 1234)
			p = track.translateOut(ep)
			track.translateOut(ep)
			track.translateOut(ep)

			track.terminate(p)
			self.assertEqual(track.isEmpty(), True)

	def test_completeProcess(self):
		track = tt.TransportationTracker()

		ep = tt.endpoint('192.168.1.1', 1234)
		p = track.translateOut(ep)

		for x in range(5):
			self.assertDuplex(track, ep, p)

		track.terminate(ep)

		self.assertEqual(track.isEmpty(), True)


	def test_multipleIPs(self):

		track = tt.TransportationTracker()

		ep1 = tt.endpoint('192.168.1.1', 1234)
		ep2 = tt.endpoint('192.168.1.2', 1234)

		p1 = track.translateOut(ep1)
		p2 = track.translateOut(ep2)

		for x in range(5):
				self.assertDuplex(track, ep1, p1)
				self.assertDuplex(track, ep2, p2)

		track.terminate(p1)
		track.terminate(p2)

		self.assertEqual(track.isEmpty(), True)

	def test_singleIPmultiplePorts(self):
		track = tt.TransportationTracker()

		eps = [tt.endpoint('192.168.1.1', 1500 + x) for x in range(200)]
		ps = [track.translateOut(ep) for ep in eps]

		self.assertEqual(len(eps), len(ps))

		for x in range(5):
			for i in range(len(eps)):
				self.assertDuplex(track, eps[i], ps[i])

		for port in ps:
			track.terminate(port)

		self.assertEqual(track.isEmpty(), True)


class TestNetutilsMethods(unittest.TestCase):

	def test_sainity(self):
		self.assertEqual(1, 1)


class TestIPSMethods(unittest.TestCase):

	def test_sainity(self):
		self.assertEqual(1, 1)


if __name__ == '__main__':
	unittest.main()
