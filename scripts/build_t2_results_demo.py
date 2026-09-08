"""Render an explicitly labelled existing-results explainer, with no model calls.

Requires Pillow only for rendering. Media encoding is a separate local Windows
step. The original package, history and data remain read-only.
"""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import wave
import zipfile

PACKAGE_SHA = "441acf1a0237401c4da953e3440c908b15f40f59ec7e7b0026a51beb4b43dcf4"
SOURCE_COMMIT = "1f48e5ed937596dc5ad1995a30eaf50f8f58f7ac"
BG, INK, SUB, TEAL, CARD = "#f3f5f7", "#15283e", "#4e6279", "#007d79", "#ffffff"


def wire(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()


def create(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)


def pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def capture(package, output, python):
    manifest = json.loads((package / "MANIFEST.json").read_bytes())
    if manifest["source_commit"] != SOURCE_COMMIT:
        raise ValueError("unexpected_source_commit")
    env = os.environ.copy()
    for name in ("DEEPSEEK_API_KEY", "OPENAI_API_KEY", "PYTHONPATH", "PYTHONHOME"):
        env.pop(name, None)
    env.update(PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
    commands = {
        "verify": (["verify_delivery.py"], package),
        "walkthrough": (["source/scripts/demo_t2_results.py", "--preview-zip", "evidence/prior-results.zip",
                         "--timeout-receipt", "evidence/diagnostic"], package),
        "cli-help": (["-m", "vulngym_agent.t2_production_cli", "--help"], package / "source"),
    }
    result = {}
    for name, (args, cwd) in commands.items():
        run = subprocess.run([str(python), "-B", *args], cwd=cwd, env=env,
                             capture_output=True, timeout=30)
        if run.returncode != 0 or run.stderr:
            raise ValueError("local_capture_failed_" + name)
        create(output / "capture" / (name + ".stdout.txt"), run.stdout)
        result[name] = {"exit_code": 0, "stderr_bytes": 0, **pin(run.stdout)}
    verified = json.loads((output / "capture/verify.stdout.txt").read_bytes())
    if not verified["verified"] or verified["files"] != 149:
        raise ValueError("delivery_verification_failed")
    with zipfile.ZipFile(package / "evidence/prior-results.zip") as archive:
        handoff = json.loads(archive.read("data/handoff.json"))
        review = json.loads(archive.read("evidence/t2-current-candidate-self-review-20260908/review.json"))
    entry, report = handoff["entries"][0], handoff["validation"][0]
    if entry["verify"] != 0 or report["verdict"] != "uncertain":
        raise ValueError("historical_verdict_changed")
    states = Counter(field["status"] for field in review["fields"].values())
    if states != {"supported": 6, "reasonable_alternative": 1, "uncertain": 2}:
        raise ValueError("review_group_changed")
    current = json.loads((package / "evidence/diagnostic/summary.json").read_bytes())
    if current["complete_candidates"] != 0 or current["actual_http_requests"] != 2:
        raise ValueError("diagnostic_counts_changed")
    create(output / "capture/metadata.json", wire({
        "kind": "local_existing_results_command_capture_not_screen_recording",
        "source_commit": SOURCE_COMMIT, "package_sha256": PACKAGE_SHA,
        "new_provider_calls": 0, "complete_T2_quality_acceptance": False,
        "commands": result, "rendering": "editorial_cards_based_on_captured_stdout_and_public_receipts",
        "narration": "offline_synthetic_voice_not_a_human_recording",
    }))
    return entry


def storyboard(entry):
    return [
        dict(title="报告 → 可复核的数据", kicker="01 / 产品定位", layout="intro",
             voice="这是题二的数据生产工具，主交验是题二，题一只作辅助检查。本片展示已经存在的真实结果和离线运行，不是现场调用模型生成新数据。接下来会同时展示已完成的内容和主要缺口。"),
        dict(title="接收方可以直接运行", kicker="02 / 实际命令输出", layout="verify",
             voice="在交接目录，先运行文件校验，再运行已有结果演示，最后打开命令行帮助。这三个命令刚刚都实际执行成功，不需要密钥，也不收费。画面是根据保存的命令输出制作的讲解卡，不是操作系统录屏。"),
        dict(title="边界清楚的生产流程", kicker="03 / 输入与控制", layout="flow",
             voice="实际生产要先准备获准的报告资料、修复信息和固定版本源码。模型在有限上下文中作选择与自检，本地控制器检查结构和证据绑定。有完整候选时送入题一；证据不足则保留明确的复核记录。它不是任意网址一键抓取器。"),
        dict(title="已有 1 份完整候选 + T1 报告", kicker="04 / 真实开发组，非新输入成绩", layout="candidate",
             candidate_title=entry["vuln_title"],
             voice="已有真实开发组包含两项任务，其中一项生成完整候选并接受了真实题一检查，另一项在自检时弃答。这里展示的候选机器验证值仍为零，题一总体仍为待定。完整输出并不等于语义正确或已经由人工验证。"),
        dict(title="评价保留支持、替代与待定", kicker="05 / 单例九维自评，分组独立", layout="review",
             voice="对这一个完整候选，九个维度的开发自评是六项支持，一项合理替代，两项待定。待定集中在版本关联和调用链完整性。这是人工智能辅助自评，不是独立人工审核；也不能和历史十二条开发评价合并成盲测分数。"),
        dict(title="弃答和执行失败不是一回事", kicker="06 / 两组结果分别报告", layout="failure",
             voice="首次新输入组有两项任务，完整产出为零，两项都是有理由的语义弃答。后来的同输入诊断实际发送两次请求：一次成功，一次超时，第二项任务没有发送。诊断没有取得新的语义判断，超时请求的服务端计费也未知。"),
        dict(title="进度与失败现在明确可见", kicker="07 / 本轮工程改进", layout="engineering",
             voice="新命令行会分别统计候选、题一报告、语义弃答和调用问题；调用出错时显示未完成并退出一。进度参数输出任务开始和结束。工作区一百零四项回归、包内六十一项测试通过，但两组有重叠，也都不代表模型质量得分。"),
        dict(title="能交接，但质量还没全部达标", kicker="08 / 当前交付与下一步", layout="closing",
             voice="交接包已经包含可运行源码、说明文档、三页设计简报，以及真实结果与评价记录。这个视频补上了已有结果的解说材料。真正剩下的重点仍是新输入的有效完整产出和逐字段质量核对；不能为了数量把不确定改成正确。"),
    ]


def render_frames(scenes, output, font_path):
    from PIL import Image, ImageDraw, ImageFont
    fonts = {n: ImageFont.truetype(str(font_path), n) for n in (19, 21, 23, 25, 27, 29, 32, 36, 44, 52, 72)}
    def wrap(draw, value, font, width):
        lines, line = [], ""
        for char in value:
            if char == "\n":
                lines.append(line); line = ""; continue
            if line and draw.textlength(line + char, font=font) > width:
                lines.append(line); line = char
            else:
                line += char
        return lines + ([line] if line else [])
    frames = []
    for index, scene in enumerate(scenes, 1):
        im = Image.new("RGB", (1280, 720), BG)
        d = ImageDraw.Draw(im)
        def text(value, xy, size=29, color=INK, width=1100, gap=12):
            x, y = xy
            for line in wrap(d, value, fonts[size], width):
                d.text((x, y), line, font=fonts[size], fill=color)
                y += size + gap
            if y > 654:
                raise ValueError("rendered_text_exceeds_content_area")
            return y
        def box(bounds, fill=CARD):
            d.rounded_rectangle(bounds, radius=20, fill=fill)
        text("VULNGYM  /  T2 → T1", (54, 30), 23, TEAL)
        text(scene["kicker"], (850, 33), 21, SUB, width=385)
        text(scene["title"], (54, 96), 44)
        layout = scene["layout"]
        if layout == "intro":
            text("把报告整理成完整候选，保留证据与不确定性。", (56, 183), 32, SUB)
            for x, title, body in [(54,"主 T2","数据生产"),(452,"辅 T1","辅助检查"),(850,"CLI + JSONL","可运行交接")]:
                box((x, 288, x + 374, 458)); text(title, (x+24, 313), 36, TEAL, width=330)
                text(body, (x+24, 381), 29, width=330)
            text("已有真实结果讲解；不是新模型生成或独立人审。", (56, 518), 29)
        elif layout == "verify":
            box((54, 190, 1226, 594), "#15283e")
            text("$ python -B verify_delivery.py", (82, 215), 27, "#9fe3d6")
            stdout = json.loads((output / "capture/verify.stdout.txt").read_bytes())
            lines = json.dumps({k: stdout[k] for k in ("verified", "files", "new_provider_calls")}, indent=2)
            text(lines, (82, 277), 29, "#f3f6fa", gap=8)
            text("演示脚本：退出 0     CLI --help：退出 0", (82, 505), 29, "#f3f6fa")
            text("原始 stdout 已随视频保留；画面是输出重排，不是屏幕录制。", (56, 613), 23, SUB)
        elif layout == "flow":
            for n, (title, body) in enumerate([("准备输入","获准资料 / 固定源码"),("模型生产","规划 / 选择 / 自检"),("保守分流","完整候选 或 defer"),("辅助交接","T1报告 / JSONL")]):
                x = 54 + n * 302
                box((x, 258, x + 267, 426)); text(title,(x+19,282),32,TEAL,width=230)
                text(body,(x+19,341),23,width=226)
                if n < 3: text("→",(x+274,314),25,TEAL,width=26)
            text("本地控制器：预算限制、schema、来源与位置绑定。", (56, 493), 29)
            text("不执行目标项目；位置对得上不等于角色或调用关系正确。", (56, 557), 25, SUB)
        elif layout == "candidate":
            box((54, 197, 1226, 344))
            text("真实候选标题",(78,211),23,TEAL)
            text(scene["candidate_title"],(78,255),29,width=1110,gap=9)
            for x, val, label in [(54,"1 / 2","开发组完整候选"),(452,"verify = 0","机器输出保持原样"),(850,"uncertain","T1总体判定")]:
                box((x,380,x+374,526)); text(val,(x+24,396),36,TEAL,width=330)
                text(label,(x+24,463),25,width=330)
            text("另一任务：reflection defer。以上均不是新输入盲测成绩。",(56,566),25,SUB)
        elif layout == "review":
            for x, value, label, color in [(54,"6","支持",TEAL),(452,"1","合理替代","#3d68a1"),(850,"2","待定","#a46520")]:
                box((x,220,x+374,435)); text(value,(x+26,232),72,color)
                text(label,(x+26,350),32)
            text("待定：版本关联、trace 完整性。",(56,482),32)
            text("AI辅助开发自评 ≠ 独立人审；不与历史12条合并分母。",(56,550),25,SUB)
        elif layout == "failure":
            for x in (54,666): box((x,210,x+560,520))
            text("首次新输入组",(78,235),32,TEAL,width=510)
            text("0 / 2 完整产出",(78,311),36,width=510)
            text("2 条语义 defer\n有具体理由，仍未产出完整候选",(78,388),25,SUB,width=510)
            text("同输入诊断组",(690,235),32,"#a46520",width=510)
            text("1 成功 + 1 超时",(690,311),36,width=510)
            text("实际 2 HTTP；第二任务未发送\n新语义判断 0；超时计费未知",(690,388),25,SUB,width=510)
            text("传输失败不能计作语义弃答，更不能算作“正确”。",(56,571),29)
        elif layout == "engineering":
            text("--progress：任务开始 / 结束写入 stderr",(56,202),32,TEAL)
            text("有调用问题：incomplete + 退出 1；保留既有证据。",(56,265),29)
            text("失败阶段：连接 / 发送 / 等响应头 / 读响应体。",(56,325),29)
            for x, val, lab in [(54,"104 项","工作区相关回归"),(666,"61 项","交接导出环境测试")]:
                box((x,417,x+560,551)); text(val,(x+24,429),44,TEAL,width=510)
                text(lab,(x+24,502),25,width=510)
            text("两组有重叠；全部是离线测试，不是模型质量分数。",(56,593),23,SUB)
        else:
            box((54,202,1226,385))
            text("可转交：源码 · 运行命令 · 设计简报 · 真实结果与评价",(78,228),29,width=1100)
            text("本视频补充已有结果讲解，不改变原始数据与历史判定。",(78,302),27,SUB,width=1100)
            text("主缺口：新输入的有效完整产出与逐字段质量核对。",(56,450),32,TEAL)
            text("宁可明确待定，不把无证据或执行失败包装成正确。",(56,527),29)
            text("全部历史key已结束使用；本片新增模型调用为 0。",(56,593),23,SUB)
        d.rectangle((0,675,1280,720),fill=INK)
        d.text((54,683),"已有真实结果  ·  非现场模型生成  ·  机器标注 verify=0",font=fonts[19],fill="#e8eef4")
        d.text((1180,683),f"{index} / {len(scenes)}",font=fonts[19],fill="#e8eef4")
        name = f"frames/scene-{index:02}.png"
        path = output / name
        path.parent.mkdir(exist_ok=True)
        with path.open("xb") as stream: im.save(stream, format="PNG")
        scene.update(index=index,image=name)
        frames.append(im.copy())
    contact = Image.new("RGB",(1280,1440),"white")
    for i, frame in enumerate(frames):
        contact.paste(frame.resize((640,360)),((i%2)*640,(i//2)*360))
    with (output / "contact-sheet.png").open("xb") as stream:
        contact.save(stream,format="PNG")


def compose_audio(output):
    scenes = json.loads((output / "storyboard.json").read_bytes())
    chunks, cursor, subtitles = [], 0, []
    expected = None
    def srt_time(seconds):
        millis = round(seconds*1000)
        return f"{millis//3600000:02}:{millis//60000%60:02}:{millis//1000%60:02},{millis%1000:03}"
    for scene in scenes:
        with wave.open(str(output / f"audio/scene-{scene['index']:02}.wav"),"rb") as wav:
            params = (wav.getnchannels(),wav.getsampwidth(),wav.getframerate(),wav.getcomptype())
            raw, count = wav.readframes(wav.getnframes()), wav.getnframes()
        if expected is None: expected=params
        if params != expected or params[:2] != (1,2) or params[3] != "NONE":
            raise ValueError("inconsistent_speech_format")
        rate=params[2]
        speech_seconds=count/rate
        # Whole 15-fps frame count; a short breathing space before/after voice.
        frame_count=max(120,int((speech_seconds+1.5)*15+0.999999))
        duration=frame_count/15
        before=round(rate*0.25)
        total=round(duration*rate)
        chunks.append(b"\0"*(before*2)+raw+b"\0"*((total-before-count)*2))
        scene.update(start_seconds=cursor,duration_seconds=duration,voice_seconds=speech_seconds)
        sentences=[s for s in scene["voice"].split("。") if s]
        offset=cursor+0.25
        weight=sum(len(s) for s in sentences)
        for sentence in sentences:
            span=speech_seconds*len(sentence)/weight
            subtitles.append(f"{len(subtitles)+1}\n{srt_time(offset)} --> {srt_time(offset+span)}\n{sentence}。\n")
            offset+=span
        cursor+=duration
    with (output / "narration.wav").open("xb") as raw:
        with wave.open(raw,"wb") as wav:
            wav.setnchannels(expected[0]); wav.setsampwidth(expected[1]); wav.setframerate(expected[2])
            wav.writeframes(b"".join(chunks))
    create(output / "timeline.json",wire({"fps":15,"seconds":cursor,"scenes":scenes,
        "subtitle_timing":"sentence timing proportional within measured per-scene synthesized audio; approximate"}))
    create(output / "narration.srt",("\n".join(subtitles)+"\n").encode("utf-8-sig"))
    print(json.dumps({"scenes":len(scenes),"seconds":round(cursor,3),"audio":"offline_synthetic_zh_CN"}))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode",choices=("prepare","audio"))
    parser.add_argument("--output",required=True,type=Path)
    parser.add_argument("--package",type=Path)
    parser.add_argument("--python",type=Path)
    parser.add_argument("--font",type=Path)
    args=parser.parse_args()
    if args.mode=="audio":
        compose_audio(args.output); return
    if args.output.exists(): raise ValueError("output_already_exists")
    if pin(args.package.with_suffix(".zip").read_bytes())["sha256"] != PACKAGE_SHA:
        raise ValueError("unexpected_package_zip")
    args.output.mkdir(parents=True)
    entry=capture(args.package,args.output,args.python)
    scenes=storyboard(entry)
    render_frames(scenes,args.output,args.font)
    create(args.output / "storyboard.json",wire(scenes))
    print(json.dumps({"prepared":True,"scenes":len(scenes),"new_provider_calls":0}))


if __name__=="__main__":
    main()
