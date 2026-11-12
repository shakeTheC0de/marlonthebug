"""Payload mutators — case flipping, encoding, injection, bypass techniques."""

import random
import string


class Mutator:
    def __init__(self) -> None:
        pass

    def mutate(self, base: str, count: int = 20) -> list[str]:
        mutations: list[str] = []
        mutations.extend(self.case_mutations(base))
        mutations.extend(self.encoding_mutations(base))
        mutations.extend(self.prefix_suffix(base))
        mutations.extend(self.whitespace_mutations(base))
        mutations.extend(self.null_byte_mutations(base))
        mutations.extend(self.comment_mutations(base))
        mutations.extend(self.newline_mutations(base))
        mutations.extend(self.nested_mutations(base))

        unique = list(dict.fromkeys(mutations))
        random.shuffle(unique)
        return unique[:count]

    @staticmethod
    def case_mutations(payload: str) -> list[str]:
        variants = [
            payload.upper(),
            payload.lower(),
            payload.title(),
            "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload)),
            payload.swapcase(),
        ]
        for word in payload.split():
            variants.append(payload.replace(word, word.upper(), 1))
            variants.append(payload.replace(word, word.lower(), 1))
        return variants

    @staticmethod
    def encoding_mutations(payload: str) -> list[str]:
        variants = []
        variants.append("".join(f"%{ord(c):02x}" for c in payload))
        variants.append("".join(f"%{ord(c):02X}" for c in payload))
        variants.append("".join(f"\\x{ord(c):02x}" for c in payload))
        variants.append("".join(f"\\u{ord(c):04x}" for c in payload))
        variants.append("".join(f"&#{ord(c)};" for c in payload))
        variants.append("".join(f"&#x{ord(c):x};" for c in payload))

        half = len(payload) // 2
        if half > 0:
            variants.append(
                "".join(f"%{ord(c):02x}" for c in payload[:half])
                + payload[half:]
            )
        return variants

    @staticmethod
    def prefix_suffix(payload: str) -> list[str]:
        prefixes = ["", " ", "\t", "/", ";", "|", "&", "$", "`", "'", '"']
        suffixes = ["", " ", "\t", ";", "|", "&", "$", "`", "'", '"', " --", " #", "/*", "*/"]
        variants = []
        for pre in prefixes:
            for suf in suffixes:
                variants.append(f"{pre}{payload}{suf}")
        return variants

    @staticmethod
    def whitespace_mutations(payload: str) -> list[str]:
        variants = []
        for space_alt in ["\\t", "\\n", "\\r", "\\v", "\\f", "%09", "%0a", "%0d", "%0b", "%0c",
                           "/**/", "+", "--%0a", "#%0a"]:
            if " " in payload:
                variants.append(payload.replace(" ", space_alt))
        return variants

    @staticmethod
    def null_byte_mutations(payload: str) -> list[str]:
        variants = []
        for pos in range(len(payload)):
            variants.append(payload[:pos] + "%00" + payload[pos:])
            variants.append(payload[:pos] + "\x00" + payload[pos:])
        variants.append(payload + "%00")
        variants.append(payload + "\x00")
        return variants

    @staticmethod
    def comment_mutations(payload: str) -> list[str]:
        comments = ["/**/", "/**/", "/*!*/", "/*!50000*/", "/**__/**/"]
        variants = []
        for comment in comments:
            if " " in payload:
                variants.append(payload.replace(" ", comment))
            for pos in range(0, len(payload), max(1, len(payload) // 3)):
                variants.append(payload[:pos] + comment + payload[pos:])
        return variants

    @staticmethod
    def newline_mutations(payload: str) -> list[str]:
        variants = []
        if " " in payload:
            for nl in ["%0a", "%0d%0a", "\\n", "\\r\\n", "\n", "\r\n"]:
                variants.append(payload.replace(" ", nl))
        return variants

    @staticmethod
    def nested_mutations(payload: str) -> list[str]:
        variants = []
        if len(payload) > 3:
            variants.append(f"{{{{{payload}}}}}")
            variants.append(f"${{{payload}}}")
            variants.append(f"<%= {payload} %>")
            variants.append(f"<?= {payload} ?>")
            variants.append(f"{{#{payload}}}")
        return variants
