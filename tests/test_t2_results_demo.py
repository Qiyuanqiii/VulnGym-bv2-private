"""Deterministic media preparation tests; no provider, real speech or video calls."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import wave

from scripts import build_t2_results_demo as demo


class ResultsDemoTests(unittest.TestCase):
    def test_storyboard_keeps_scope_and_outcome_groups_explicit(self):
        scenes=demo.storyboard({"vuln_title":"Example candidate"})
        self.assertEqual(len(scenes),8)
        self.assertIn("不是现场调用模型",scenes[0]["voice"])
        self.assertEqual(scenes[3]["candidate_title"],"Example candidate")
        self.assertIn("不是独立人工审核",scenes[4]["voice"])
        self.assertIn("完整产出为零",scenes[5]["voice"])
        self.assertIn("第二项任务没有发送",scenes[5]["voice"])
        self.assertIn("两组有重叠",scenes[6]["voice"])

    def test_create_is_exclusive(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"evidence.json"
            demo.create(path,b"original")
            with self.assertRaises(FileExistsError): demo.create(path,b"changed")
            self.assertEqual(path.read_bytes(),b"original")

    def test_wrong_source_is_rejected_before_command_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            demo.create(root/"MANIFEST.json",demo.wire({"source_commit":"wrong"}))
            with patch.object(demo.subprocess,"run") as run:
                with self.assertRaisesRegex(ValueError,"unexpected_source_commit"):
                    demo.capture(root,root,Path("python"))
            run.assert_not_called()

    def audio_fixture(self,root,channels=1):
        scenes=[{"index":1,"voice":"第一句。第二句。"},{"index":2,"voice":"最后一句。"}]
        demo.create(root/"storyboard.json",demo.wire(scenes))
        (root/"audio").mkdir()
        for index in (1,2):
            with wave.open(str(root/f"audio/scene-{index:02}.wav"),"wb") as wav:
                wav.setnchannels(channels if index==2 else 1)
                wav.setsampwidth(2); wav.setframerate(22050)
                wav.writeframes(b"\x01\x00"*2205*(channels if index==2 else 1))

    def test_audio_timeline_and_subtitles_cover_scenes_without_live_waits(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); self.audio_fixture(root)
            with patch("builtins.print"): demo.compose_audio(root)
            timeline=json.loads((root/"timeline.json").read_bytes())
            self.assertEqual(timeline["seconds"],16)
            self.assertEqual(timeline["scenes"][1]["start_seconds"],8)
            self.assertEqual(timeline["fps"],15)
            self.assertIn("approximate",timeline["subtitle_timing"])
            with wave.open(str(root/"narration.wav"),"rb") as wav:
                self.assertEqual(wav.getnframes()/wav.getframerate(),16)
                self.assertEqual(wav.getnchannels(),1)
            captions=(root/"narration.srt").read_text(encoding="utf-8-sig")
            self.assertIn("00:00:00,250",captions)
            self.assertIn("00:00:08,250",captions)

    def test_inconsistent_audio_preserves_scene_inputs_and_does_not_publish(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); self.audio_fixture(root,channels=2)
            with self.assertRaisesRegex(ValueError,"inconsistent_speech_format"):
                demo.compose_audio(root)
            self.assertFalse((root/"narration.wav").exists())
            self.assertFalse((root/"timeline.json").exists())
            self.assertTrue((root/"audio/scene-01.wav").exists())


if __name__=="__main__": unittest.main()
