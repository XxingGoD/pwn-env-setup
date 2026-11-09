import unittest
from pwn_env.catalog import CatalogError, resolve, select_categories, load_catalog
from pwn_env.platforms import detect_platform

class SelectionTests(unittest.TestCase):
    def test_categories_resolve_dependencies_once(self):
        data, tools = load_catalog()
        selected = select_categories(["debug", "rop"], data, tools)
        self.assertEqual(len(selected), len(set(selected)))
        self.assertIn("pwntools", selected)
    def test_unknown_tool_rejected(self):
        with self.assertRaises(CatalogError): resolve(["not-a-tool"])
    def test_dependency_cycle_rejected(self):
        with self.assertRaises(CatalogError): resolve(["a"], {"a":{"depends_on":["b"]},"b":{"depends_on":["a"]}})
    def test_platform_exact(self):
        self.assertEqual(detect_platform({"ID":"ubuntu","VERSION_ID":"22.04"},"x86_64"),"ubuntu22.04")
        with self.assertRaises(ValueError): detect_platform({"ID":"linuxmint","ID_LIKE":"ubuntu"},"x86_64")
if __name__ == "__main__": unittest.main()
