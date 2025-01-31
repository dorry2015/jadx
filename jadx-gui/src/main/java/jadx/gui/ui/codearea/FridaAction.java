package jadx.gui.ui.codearea;

import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.util.List;
import javax.swing.AbstractAction;
import javax.swing.KeyStroke;
import org.jetbrains.annotations.Nullable;
import jadx.core.dex.info.MethodInfo;
import jadx.core.dex.instructions.args.ArgType;
import jadx.core.dex.nodes.ClassNode;
import jadx.core.dex.nodes.MethodNode;
import jadx.gui.treemodel.JNode;
import jadx.gui.utils.UiUtils;
import jadx.gui.treemodel.JClass;
import jadx.gui.treemodel.JMethod;
import static javax.swing.KeyStroke.getKeyStroke;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class FridaAction extends JNodeMenuAction<JNode> {
	private static final long serialVersionUID = -1186470538894941302L;
	private static final Logger LOG = LoggerFactory.getLogger(FridaAction.class);

	public FridaAction(CodeArea codeArea) {
		super(("Frida Script"), codeArea);
		KeyStroke key = getKeyStroke(KeyEvent.VK_F, 0);
		codeArea.getInputMap().put(key, "frida copy");
		codeArea.getActionMap().put("frida copy", new AbstractAction() {
			@Override
			public void actionPerformed(ActionEvent e) {
				node = getNodeByOffset(codeArea.getWordStart(codeArea.getCaretPosition()));
				doFrida();
			}
		});
	}

	private static String convertType(String type) {
		if (!type.endsWith("[]")) {
			return type;
		}
		String typeResult = "";
		while (type.endsWith("[]")) {
			typeResult += "[";
			type = type.substring(0, type.length() - 2);
		}
		switch (type) {
			case "int":
				typeResult += "I";
				break;
			case "boolean":
				typeResult += "Z";
				break;
			case "byte":
				typeResult += "B";
				break;
			case "char":
				typeResult += "C";
				break;
			case "double":
				typeResult += "D";
				break;
			case "float":
				typeResult += "F";
				break;
			case "long":
				typeResult += "J";
				break;
			case "short":
				typeResult += "S";
				break;
			default:
				typeResult += "L" + type + ";";
				break;
		}
		return typeResult;
	}

	private String formatClassName(MethodInfo methodInfo) {
		// String className = methodInfo.getDeclClass().getType().getObject();
		String className = methodInfo.getDeclClass().getAliasShortName();
		if (className.length() <= 3) {
			className = methodInfo.getDeclClass().getAliasFullName();
		}
		String classNameVar = className.replace("$", "_");
		classNameVar = classNameVar.replace("-", "_");
		classNameVar = classNameVar.replace(".", "_");
		classNameVar += "_cls";
		return classNameVar;
	}

	private String generateFunctionScope(MethodInfo methodInfo, boolean bhead, String methodName) {
		if (bhead) {
			String className = methodInfo.getDeclClass().getAliasShortName();
			if (methodName == null || methodName.isEmpty())
				return String.format("function hookJS_%s() {\n", className);
			else
				return String.format("function hookJS_%s_%s() {\n", className, methodName);
		}
		return "}\n";
	}

	private String generateClassDefinition(MethodInfo methodInfo, String classNameVar) {
		String className = methodInfo.getDeclClass().getType().getObject();
		return String.format("    let %s = Java.use('%s');\n", classNameVar, className);
	}

	private String generateMethod(MethodInfo methodInfo, String classNameVar) {
		if (methodInfo.isClassInit()) {
			return "";
		}
		String methodName = methodInfo.getName();
		List<ArgType> argTypes = methodInfo.getArgumentsTypes();
		String arguments = "";
		String params = "";
		for (int i = 0; i < argTypes.size(); i++) {
			ArgType arg = argTypes.get(i);
			arguments = arguments + "'" + convertType(arg.toString()) + "', ";
			params = params + "v" + i + ", ";
		}
		if (arguments.length() > 0) {
			arguments = arguments.substring(0, arguments.length() - 2);
			params = params.substring(0, params.length() - 2);

		}
		if (methodInfo.isConstructor()) {
			methodName = "$init";
		}
		StringBuffer sb = new StringBuffer();
		sb.append(String.format("    %s.%s.overload(%s).implementation = function(%s){\n", classNameVar, methodName,
				arguments, params));
		sb.append("        let invokeId = INVOKEID++;\n        ");
		if (methodInfo.isConstructor() == false && methodInfo.getReturnType().isVoid() == false) {
			sb.append("let ret = ");
		}
		sb.append(String.format("this.%s(%s);\n", methodName, params));
		String hasRet = "ret";
		if (methodInfo.getReturnType().isVoid() == true){
			hasRet = "undefined";
		}
		sb.append(String.format("        printMethod(invokeId, false, false, arguments, %s, '%s');\n",
		hasRet, methodInfo.toString()));
		if (methodInfo.isConstructor() == false && methodInfo.getReturnType().isVoid() == false) {
			sb.append("        return ret;\n");
		}
		sb.append("    }\n");
		return sb.toString();
	}

	private void doFrida() {
		if (node != null) {
			System.out.println(node.getClass().getName());
			String classNameVar = "";
			String classDefStr = "";
			String methodStr = "";
			String functionScopeHead = "";
			String functionScopeTail = "";
			boolean canSet = false;
			if (node.getClass().getName().equals(JMethod.class.getName())) {
				canSet = true;
				JMethod jMethod = (JMethod) node;
				MethodInfo methodInfo = jMethod.getJavaMethod().getMethodNode().getMethodInfo();
				functionScopeHead = generateFunctionScope(methodInfo, true, methodInfo.getName());
				classNameVar = formatClassName(methodInfo);
				classDefStr = generateClassDefinition(methodInfo, classNameVar);
				methodStr = generateMethod(methodInfo, classNameVar);
				functionScopeTail = generateFunctionScope(methodInfo, false, methodInfo.getName());
			} else if (node.getClass().getName().equals(JClass.class.getName())) {
				canSet = true;
				JClass jClass = (JClass) node;
				ClassNode clsNode = jClass.getCls().getClassNode();
				List<MethodNode> methods = clsNode.getMethods();
				for (int i = 0; i < methods.size(); i++) {
					MethodNode method = methods.get(i);
					MethodInfo methodInfo = method.getMethodInfo();
					if (i == 0) {
						functionScopeHead = generateFunctionScope(methodInfo, true, null);
						classNameVar = formatClassName(methodInfo);
						classDefStr = generateClassDefinition(methodInfo, classNameVar);
						functionScopeTail = generateFunctionScope(methodInfo, false, null);
					}
					methodStr += generateMethod(methodInfo, classNameVar);
				}				
			}
			if (canSet) {
				String resultStr = functionScopeHead + classDefStr + methodStr + functionScopeTail;
				System.out.println(resultStr);
				UiUtils.setClipboardString(resultStr);
			}
			node = null;
		}
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		doFrida();
	}

	@Nullable
	@Override
	public JNode getNodeByOffset(int offset) {
		return codeArea.getJNodeAtOffset(offset);
	}
}