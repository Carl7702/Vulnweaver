# GPU-only serving image. Model weights are mounted at runtime, never baked in.
FROM vllm/vllm-openai:v0.6.6.post1

ENTRYPOINT ["python3", "-m", "vllm.entrypoints.openai.api_server"]
CMD ["--model", "Qwen/Qwen2.5-Coder-32B-Instruct", "--dtype", "bfloat16"]

