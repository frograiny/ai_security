from setuptools import setup, find_packages

setup(
    name="ai_waf_shield",
    version="1.0.0",
    description="Enterprise Deep-Learning Protection Middleware for Flask",
    author="AI Security Project",
    packages=find_packages(),
    install_requires=[
        "Flask",
    ],
    # Do not enforce tensorflow as a hard requirement for simple setups
    extras_require={
        "ai": ["tensorflow"],
    }
)
