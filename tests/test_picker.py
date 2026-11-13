import threading
import time
import unittest

from sumproofy.picker import MainThreadPicker, make_picker


class PickerCase(unittest.TestCase):
    def test_pick_round_trip(self):
        picker = MainThreadPicker(timeout=5)
        stop = threading.Event()

        def fake_main_thread():
            while not stop.is_set():
                picker.service_one(lambda: "/tmp/chosen.exe")

        t = threading.Thread(target=fake_main_thread, daemon=True)
        t.start()
        try:
            self.assertEqual(picker.pick(), "/tmp/chosen.exe")
        finally:
            stop.set()

    def test_pick_times_out_to_none(self):
        picker = MainThreadPicker(timeout=0.2)
        start = time.time()
        self.assertIsNone(picker.pick())
        self.assertLess(time.time() - start, 5)

    def test_dialog_exception_becomes_none(self):
        picker = MainThreadPicker(timeout=5)
        def boom():
            raise RuntimeError("no display")
        def worker():
            self.assertIsNone(picker.pick())
        t = threading.Thread(target=worker)
        t.start()
        self.assertTrue(picker.service_one(boom))
        t.join(5)
        self.assertFalse(t.is_alive())

    def test_disabled_picker(self):
        picker, run = make_picker(disabled=True)
        self.assertIsNone(picker)


if __name__ == "__main__":
    unittest.main()
