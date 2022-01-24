from gsdml_parser import XMLDevice


device = XMLDevice("./gsdml/test_project.xml")

print(device.body.dap_list[0].usable_modules[0].f_parameters.attributes)