from setuptools import setup, find_packages

setup(
    name="TRAP_for_SAT_2025",
    version="1.0.0",
    description="A TRAP for SAT: Transistor-Level Programmable Fabric & SAT Attack Toolset (2025 Q1 Research Paper)",
    author="Aric Fowler",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "z3-solver>=4.12.0",
    ],
    entry_points={
        "console_scripts": [
            "satAttack=src.satAttack_cli:main",
            "satVerify=src.satVerify_cli:main",
            "trapFabricBuilder=src.trapFabricBuilder_cli:main",
        ],
    },
)
