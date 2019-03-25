package gosec

import (
	_ "fmt"
	"go/ast"
	"go/token"
	"path"
	_ "reflect"
)

type packageDetails struct {
	packageName  string
	constructor  string
	functionList []string
}

type pkgFunctions struct {
	constructor  string
	functionList []string
}

type varState struct {
	tainted   bool
	used      bool
	validated bool
}

type inputVariables struct {
	filename      string
	functionName  string
	variableName  string
	variableState varState
	node 		  ast.Node
	columnNumber  int
}

type FuncVisitor struct {
	rhsIdents []string
}

type CallExpressions struct {
	funcCalls []*ast.CallExpr
}

func (v *FuncVisitor) Visit(n ast.Node) (w ast.Visitor) {
	switch t := n.(type) {
	case *ast.Ident:
		v.rhsIdents = append(v.rhsIdents, t.Name)
	}
	return v
}

func (v *CallExpressions) Visit(n ast.Node) (w ast.Visitor) {
	switch t := n.(type) {
	case *ast.CallExpr:
		v.funcCalls = append(v.funcCalls, t)
	}
	return v
}

func checkFuncDecl(fnDecl *ast.FuncDecl) (string, bool) {
	for _, arg := range fnDecl.Type.Params.List {
		if expr, ok := arg.Type.(*ast.StarExpr); ok {
			if id, ok := expr.X.(*ast.SelectorExpr); ok {
				if pkg, ok := id.X.(*ast.Ident); ok {
					if pkg.Name+"."+id.Sel.Name == "http.Request" {
						return arg.Names[0].Name, true
					}
				}
			}
		}
	}
	return "", false
}

func checkValidateConstructor(assignmentStatement *ast.AssignStmt, validationPackages map[string]*pkgFunctions) (string, string, bool) {
	if callExpr, ok := assignmentStatement.Rhs[0].(*ast.CallExpr); ok {
		if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
			if pkg, ok := selExpr.X.(*ast.Ident); ok {
				if val, ok := validationPackages[pkg.Name]; ok && val.constructor == selExpr.Sel.Name {
					if lhs, ok := assignmentStatement.Lhs[0].(*ast.Ident); ok {
						return pkg.Name, lhs.Name, true
					}
				}
			}
		}

	}
	return "", "", false
}

func findTatintedVariables(fset *token.FileSet, assignmentStatement *ast.AssignStmt, flaggedVars []inputVariables, taintedVars []string, filename string, functionName string) ([]inputVariables, []string) {
	a1 := new(FuncVisitor)
	a1.rhsIdents = a1.rhsIdents[:0]
	for _, rhs := range assignmentStatement.Rhs {
		ast.Walk(a1, rhs)
	}
	flag := false
	for _, taintVar := range taintedVars {
		for _, rhsVar := range a1.rhsIdents {
			if taintVar == rhsVar {
				flag = true
			}
		}
	}
	if flag == true {
		for _, lhs := range assignmentStatement.Lhs {
			lhsVar := lhs.(*ast.Ident)

			var tempWarningInputVar inputVariables //Declare temperary variable of type inputVariables

			tempWarningInputVar.filename = filename
			tempWarningInputVar.functionName = functionName
			tempWarningInputVar.variableName = lhsVar.Name
			tempWarningInputVar.variableState.tainted = true
			tempWarningInputVar.node = assignmentStatement
			//tempWarningInputVar.columnNumber = fset.Position(lhsVar.Pos()).Column

			flaggedVars = append(flaggedVars, tempWarningInputVar)              //Append the LHS to warning input vars array
			taintedVars = append(taintedVars, tempWarningInputVar.variableName) //Appending variable name into tainted list

		}
	}
	for _, rhsVar := range a1.rhsIdents { //Does not mutate the array
		for index := range flaggedVars {
			if rhsVar == flaggedVars[index].variableName && flaggedVars[index].variableState.tainted == true {
				tempWIV := &flaggedVars[index]
				tempWIV.variableState.used = true
			}
		}
	}
	return flaggedVars, taintedVars
}

func checkValidateFunctions(statement ast.Stmt, validationPackages map[string]*pkgFunctions) []string {
	n := new(CallExpressions)
	n.funcCalls = n.funcCalls[:0]
	ast.Walk(n, statement)
	validatedVars := make([]string, 0)
	for _, callExpr := range n.funcCalls {
		if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
			if pkg, ok := selExpr.X.(*ast.Ident); ok {
				if val, ok := validationPackages[pkg.Name]; ok {
					for _, f := range val.functionList {

						if selExpr.Sel.Name == f {

							for _, argument := range callExpr.Args {
								if arg, ok := argument.(*ast.Ident); ok {
									validatedVars = append(validatedVars, arg.Name)
								}
							}
						}
					}
				}

			}
		}

	}
	return validatedVars
}

func TaintAnalysis(gosec *Analyzer) {

	/////////////////////// Configuration Variables///////////////////

	packages := make(map[string]*packageDetails)
	packages["\"github.com/thedevsaddam/govalidator\""] = &packageDetails{packageName: "govalidator", constructor: "New", functionList: []string{"Validate"}} //Validate function takes no arguments, Request variable is passed to the constructor and the request variable is validated
	packages["\"gopkg.in/go-playground/validator.v9\""] = &packageDetails{packageName: "validator", constructor: "New", functionList: []string{"Struct", "Var"}}

	validationPackages := make(map[string]*pkgFunctions)

	////////////////////////////////////////////////////////////////

	filename := gosec.context.FileSet.File(gosec.context.Root.Package).Name()
	filename = path.Base(filename)

	fset := gosec.context.FileSet
	node := gosec.context.Root

	for _, i := range node.Imports {
		if val, ok := packages[i.Path.Value]; ok {
			if i.Name != nil {
				validationPackages[i.Name.Name] = &pkgFunctions{constructor: val.constructor, functionList: val.functionList}
			} else {
				validationPackages[val.packageName] = &pkgFunctions{constructor: val.constructor, functionList: val.functionList}
			}
		}
	}

	//Variables that have been flagged unsafe
	flaggedVars := make([]inputVariables, 0)

	for _, dec := range node.Decls {
		if fnDecl, ok := dec.(*ast.FuncDecl); ok {
			if v, ok := checkFuncDecl(fnDecl); ok {
				//Tainted variables found within a function
				taintedVars := []string{v}

				b := *fnDecl.Body
				for _, statement := range b.List {
					validatedVars := checkValidateFunctions(statement, validationPackages)

					for _, variable := range validatedVars {
						for index := range flaggedVars {
							if flaggedVars[index].variableName == variable {
								temp := &flaggedVars[index]
								temp.variableState.validated = true
								temp.variableState.tainted = false
							}
						}
						for index := range taintedVars {
							if variable == taintedVars[index] {
								taintedVars[len(taintedVars)-1], taintedVars[index] = taintedVars[index], taintedVars[len(taintedVars)-1]
								taintedVars = taintedVars[:len(taintedVars)-1]
								break
							}
						}
					}

					if assignStmt, ok := statement.(*ast.AssignStmt); ok {
						if pkg, obj, err := checkValidateConstructor(assignStmt, validationPackages); err {
							validationPackages[obj] = &pkgFunctions{constructor: validationPackages[pkg].constructor, functionList: validationPackages[pkg].functionList}
						}
						flaggedVars, taintedVars = findTatintedVariables(fset, assignStmt, flaggedVars, taintedVars, filename, fnDecl.Name.Name)
					}
				}

//				fmt.Printf("\n###############################\n")
				for _, i := range flaggedVars {
//					fmt.Printf("%s,%s:%s - %#v\n", i.filename, i.functionName, i.variableName, i.variableState)
					//fmt.Printf("[%3d:%3d]%s,%s:%s - %#v\n", i.lineNumber, i.columnNumber, i.filename, i.functionName, i.variableName, i.variableState)
					if (i.variableState.tainted == true && i.variableState.used == true) {
						issue := NewIssue(gosec.context, i.node, "TaintAnalysis", "Variable tainted with user input and used before validation", Medium, Low)
						gosec.issues = append(gosec.issues, issue)
						gosec.stats.NumFound++						
					}
				}
//				fmt.Printf("\n###############################\n")
			}
		}

	}
}
