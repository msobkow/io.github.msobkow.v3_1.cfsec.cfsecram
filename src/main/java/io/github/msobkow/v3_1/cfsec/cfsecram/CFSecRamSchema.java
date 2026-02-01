// Description: Java 25 implementation of an in-memory RAM CFSec schema.

/*
 *	io.github.msobkow.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	This file is part of Mark's Code Fractal CFSec.
 *	
 *	Mark's Code Fractal CFSec is available under dual commercial license from
 *	Mark Stephen Sobkow, or under the terms of the GNU Library General Public License,
 *	Version 3 or later.
 *	
 *	Mark's Code Fractal CFSec is free software: you can redistribute it and/or
 *	modify it under the terms of the GNU Library General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *	
 *	Mark's Code Fractal CFSec is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU Library General Public License
 *	along with Mark's Code Fractal CFSec.  If not, see <https://www.gnu.org/licenses/>.
 *	
 *	If you wish to modify and use this code without publishing your changes in order to
 *	tie it to proprietary code, please contact Mark Stephen Sobkow
 *	for a commercial license at mark.sobkow@gmail.com
 *	
 */

package io.github.msobkow.v3_1.cfsec.cfsecram;

import java.lang.reflect.*;
import java.net.*;
import java.sql.*;
import java.text.*;
import java.util.*;
import io.github.msobkow.v3_1.cflib.*;
import io.github.msobkow.v3_1.cflib.dbutil.*;

import io.github.msobkow.v3_1.cfsec.cfsec.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;
import io.github.msobkow.v3_1.cfsec.cfsec.buff.*;
import io.github.msobkow.v3_1.cfsec.cfsecsaxloader.*;

public class CFSecRamSchema
	extends CFSecBuffSchema
	implements ICFSecSchema
{
	protected short nextISOCcyIdGenValue = 1;
	protected short nextISOCtryIdGenValue = 1;
	protected short nextISOLangIdGenValue = 1;
	protected short nextISOTZoneIdGenValue = 1;
	protected long nextClusterIdGenValue = 1;


	public CFSecRamSchema() {
		super();
		tableCluster = new CFSecRamClusterTable( this );
		tableHostNode = new CFSecRamHostNodeTable( this );
		tableISOCcy = new CFSecRamISOCcyTable( this );
		tableISOCtry = new CFSecRamISOCtryTable( this );
		tableISOCtryCcy = new CFSecRamISOCtryCcyTable( this );
		tableISOCtryLang = new CFSecRamISOCtryLangTable( this );
		tableISOLang = new CFSecRamISOLangTable( this );
		tableISOTZone = new CFSecRamISOTZoneTable( this );
		tableSecDevice = new CFSecRamSecDeviceTable( this );
		tableSecGroup = new CFSecRamSecGroupTable( this );
		tableSecGrpInc = new CFSecRamSecGrpIncTable( this );
		tableSecGrpMemb = new CFSecRamSecGrpMembTable( this );
		tableSecSession = new CFSecRamSecSessionTable( this );
		tableSecUser = new CFSecRamSecUserTable( this );
		tableService = new CFSecRamServiceTable( this );
		tableServiceType = new CFSecRamServiceTypeTable( this );
		tableSysCluster = new CFSecRamSysClusterTable( this );
		tableTSecGroup = new CFSecRamTSecGroupTable( this );
		tableTSecGrpInc = new CFSecRamTSecGrpIncTable( this );
		tableTSecGrpMemb = new CFSecRamTSecGrpMembTable( this );
		tableTenant = new CFSecRamTenantTable( this );
	}

	@Override
	public ICFSecSchema newSchema() {
		throw new CFLibMustOverrideException( getClass(), "newSchema" );
	}

	@Override
	public short nextISOCcyIdGen() {
		short next = nextISOCcyIdGenValue++;
		return( next );
	}

	@Override
	public short nextISOCtryIdGen() {
		short next = nextISOCtryIdGenValue++;
		return( next );
	}

	@Override
	public short nextISOLangIdGen() {
		short next = nextISOLangIdGenValue++;
		return( next );
	}

	@Override
	public short nextISOTZoneIdGen() {
		short next = nextISOTZoneIdGenValue++;
		return( next );
	}

	@Override
	public long nextClusterIdGen() {
		long next = nextClusterIdGenValue++;
		return( next );
	}

	@Override
	public CFLibDbKeyHash256 nextSecSessionIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextSecUserIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextServiceTypeIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextTenantIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextHostNodeIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextSecGroupIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextSecGrpIncIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextSecGrpMembIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextServiceIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextTSecGroupIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextTSecGrpIncIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextTSecGrpMembIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	public String fileImport( CFSecAuthorization Authorization,
		String fileName,
		String fileContent )
	{
		final String S_ProcName = "fileImport";
		if( ( fileName == null ) || ( fileName.length() <= 0 ) ) {
			throw new CFLibNullArgumentException( getClass(),
				S_ProcName,
				1,
				"fileName" );
		}
		if( ( fileContent == null ) || ( fileContent.length() <= 0 ) ) {
			throw new CFLibNullArgumentException( getClass(),
				S_ProcName,
				2,
				"fileContent" );
		}

		CFSecSaxLoader saxLoader = new CFSecSaxLoader();
		ICFSecSchemaObj schemaObj = new CFSecSchemaObj();
		schemaObj.setCFSecBackingStore( this );
		saxLoader.setSchemaObj( schemaObj );
		ICFSecClusterObj useCluster = schemaObj.getClusterTableObj().readClusterByIdIdx( Authorization.getSecClusterId() );
		ICFSecTenantObj useTenant = schemaObj.getTenantTableObj().readTenantByIdIdx( Authorization.getSecTenantId() );
		CFLibCachedMessageLog runlog = new CFLibCachedMessageLog();
		saxLoader.setLog( runlog );
		saxLoader.setUseCluster( useCluster );
		saxLoader.setUseTenant( useTenant );
		saxLoader.parseStringContents( fileContent );
		String logFileContent = runlog.getCacheContents();
		if( logFileContent == null ) {
			logFileContent = "";
		}

		return( logFileContent );
	}

		
	@Override
	public void wireTableTableInstances() {
		if (tableCluster == null || !(tableCluster instanceof CFSecRamClusterTable)) {
			tableCluster = new CFSecRamClusterTable(this);
		}
		if (tableHostNode == null || !(tableHostNode instanceof CFSecRamHostNodeTable)) {
			tableHostNode = new CFSecRamHostNodeTable(this);
		}
		if (tableISOCcy == null || !(tableISOCcy instanceof CFSecRamISOCcyTable)) {
			tableISOCcy = new CFSecRamISOCcyTable(this);
		}
		if (tableISOCtry == null || !(tableISOCtry instanceof CFSecRamISOCtryTable)) {
			tableISOCtry = new CFSecRamISOCtryTable(this);
		}
		if (tableISOCtryCcy == null || !(tableISOCtryCcy instanceof CFSecRamISOCtryCcyTable)) {
			tableISOCtryCcy = new CFSecRamISOCtryCcyTable(this);
		}
		if (tableISOCtryLang == null || !(tableISOCtryLang instanceof CFSecRamISOCtryLangTable)) {
			tableISOCtryLang = new CFSecRamISOCtryLangTable(this);
		}
		if (tableISOLang == null || !(tableISOLang instanceof CFSecRamISOLangTable)) {
			tableISOLang = new CFSecRamISOLangTable(this);
		}
		if (tableISOTZone == null || !(tableISOTZone instanceof CFSecRamISOTZoneTable)) {
			tableISOTZone = new CFSecRamISOTZoneTable(this);
		}
		if (tableSecDevice == null || !(tableSecDevice instanceof CFSecRamSecDeviceTable)) {
			tableSecDevice = new CFSecRamSecDeviceTable(this);
		}
		if (tableSecGroup == null || !(tableSecGroup instanceof CFSecRamSecGroupTable)) {
			tableSecGroup = new CFSecRamSecGroupTable(this);
		}
		if (tableSecGrpInc == null || !(tableSecGrpInc instanceof CFSecRamSecGrpIncTable)) {
			tableSecGrpInc = new CFSecRamSecGrpIncTable(this);
		}
		if (tableSecGrpMemb == null || !(tableSecGrpMemb instanceof CFSecRamSecGrpMembTable)) {
			tableSecGrpMemb = new CFSecRamSecGrpMembTable(this);
		}
		if (tableSecSession == null || !(tableSecSession instanceof CFSecRamSecSessionTable)) {
			tableSecSession = new CFSecRamSecSessionTable(this);
		}
		if (tableSecUser == null || !(tableSecUser instanceof CFSecRamSecUserTable)) {
			tableSecUser = new CFSecRamSecUserTable(this);
		}
		if (tableService == null || !(tableService instanceof CFSecRamServiceTable)) {
			tableService = new CFSecRamServiceTable(this);
		}
		if (tableServiceType == null || !(tableServiceType instanceof CFSecRamServiceTypeTable)) {
			tableServiceType = new CFSecRamServiceTypeTable(this);
		}
		if (tableSysCluster == null || !(tableSysCluster instanceof CFSecRamSysClusterTable)) {
			tableSysCluster = new CFSecRamSysClusterTable(this);
		}
		if (tableTenant == null || !(tableTenant instanceof CFSecRamTenantTable)) {
			tableTenant = new CFSecRamTenantTable(this);
		}
		if (tableTSecGroup == null || !(tableTSecGroup instanceof CFSecRamTSecGroupTable)) {
			tableTSecGroup = new CFSecRamTSecGroupTable(this);
		}
		if (tableTSecGrpInc == null || !(tableTSecGrpInc instanceof CFSecRamTSecGrpIncTable)) {
			tableTSecGrpInc = new CFSecRamTSecGrpIncTable(this);
		}
		if (tableTSecGrpMemb == null || !(tableTSecGrpMemb instanceof CFSecRamTSecGrpMembTable)) {
			tableTSecGrpMemb = new CFSecRamTSecGrpMembTable(this);
		}
	}
}
