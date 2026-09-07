# llm/client.py

import json
import os
import re

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer


LLM_MODEL = os.getenv(
    "LLM_MODEL",
    "Qwen/Qwen2.5-0.5B-Instruct"
)

_tokenizer = None
_model = None


def load_model():
    global _tokenizer, _model

    if _tokenizer is not None and _model is not None:
        return _tokenizer, _model

    print(f"[LLM LOAD] model={LLM_MODEL}")
    print("[LLM LOAD] loading Hugging Face model...")

    _tokenizer = AutoTokenizer.from_pretrained(
        LLM_MODEL
    )

    _model = AutoModelForCausalLM.from_pretrained(
        LLM_MODEL,
        torch_dtype="auto",
        low_cpu_mem_usage=True
    )

    # GPU 있으면 자동 사용
    if torch.cuda.is_available():
        device = "cuda"
    else:
        device = "cpu"

    _model.to(device)
    _model.eval()

    print(
        f"[LLM READY] "
        f"model={LLM_MODEL} "
        f"device={device}"
    )

    return _tokenizer, _model


def generate_json(
    system_prompt,
    user_prompt,
    max_new_tokens=128
):
    if os.getenv("DISABLE_LOCAL_LLM") == "1":
        raise RuntimeError("Local LLM disabled on Render")

    tokenizer, model = load_model()

    messages = [
        {
            "role": "system",
            "content": system_prompt
        },
        {
            "role": "user",
            "content": user_prompt
        }
    ]

    text = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True
    )

    inputs = tokenizer(
        [text],
        return_tensors="pt"
    )

    inputs = {
        key: value.to(model.device)
        for key, value in inputs.items()
    }

    with torch.inference_mode():

        generated_ids = model.generate(
            **inputs,

            max_new_tokens=max_new_tokens,

            # 데모에서는 deterministic하게
            do_sample=False,

            pad_token_id=tokenizer.eos_token_id,
            eos_token_id=tokenizer.eos_token_id
        )

    # 입력 prompt 부분 제거
    generated_ids = generated_ids[
        :,
        inputs["input_ids"].shape[1]:
    ]

    output = tokenizer.batch_decode(
        generated_ids,
        skip_special_tokens=True
    )[0]

    print(
        f"[LLM] model={LLM_MODEL}"
    )

    print(
        f"[LLM RAW] {output}"
    )

    return parse_json_response(
        output
    )


def parse_json_response(text):
    """
    ```json ... ``` 또는 앞뒤 설명이 붙어도
    JSON object를 최대한 추출한다.
    """

    text = text.strip()

    # Markdown fence 제거
    text = re.sub(
        r"^```(?:json)?\s*",
        "",
        text,
        flags=re.IGNORECASE
    )

    text = re.sub(
        r"\s*```$",
        "",
        text
    )

    try:
        return json.loads(text)

    except json.JSONDecodeError:
        pass

    # 앞뒤 설명이 붙었을 경우
    start = text.find("{")
    end = text.rfind("}")

    if start != -1 and end != -1 and end > start:

        candidate = text[
            start:end + 1
        ]

        return json.loads(candidate)

    raise ValueError(
        f"LLM JSON parsing failed: {text}"
    )