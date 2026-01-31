
// Description: Java 25 in-memory RAM DbIO implementation for Cluster.

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

import java.math.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import io.github.msobkow.v3_1.cflib.*;
import io.github.msobkow.v3_1.cflib.dbutil.*;

import io.github.msobkow.v3_1.cfsec.cfsec.*;
import io.github.msobkow.v3_1.cfsec.cfsec.buff.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamClusterTable in-memory RAM DbIO implementation
 *	for Cluster.
 */
public class CFSecRamClusterTable
	implements ICFSecClusterTable
{
	private ICFSecSchema schema;
	private Map< Long,
				CFSecBuffCluster > dictByPKey
		= new HashMap< Long,
				CFSecBuffCluster >();
	private Map< CFSecBuffClusterByUDomNameIdxKey,
			CFSecBuffCluster > dictByUDomNameIdx
		= new HashMap< CFSecBuffClusterByUDomNameIdxKey,
			CFSecBuffCluster >();
	private Map< CFSecBuffClusterByUDescrIdxKey,
			CFSecBuffCluster > dictByUDescrIdx
		= new HashMap< CFSecBuffClusterByUDescrIdxKey,
			CFSecBuffCluster >();

	public CFSecRamClusterTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffCluster ensureRec(ICFSecCluster rec) {
		if (rec == null) {
			return( null );
		}
		else {
			int classCode = rec.getClassCode();
			if (classCode == ICFSecCluster.CLASS_CODE) {
				return( ((CFSecBuffClusterDefaultFactory)(schema.getFactoryCluster())).ensureRec((ICFSecCluster)rec) );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), "ensureRec", "rec", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	public ICFSecCluster createCluster( ICFSecAuthorization Authorization,
		ICFSecCluster iBuff )
	{
		final String S_ProcName = "createCluster";
		
		CFSecBuffCluster Buff = (CFSecBuffCluster)ensureRec(iBuff);
		Long pkey;
		pkey = schema.nextClusterIdGen();
		Buff.setRequiredId( pkey );
		CFSecBuffClusterByUDomNameIdxKey keyUDomNameIdx = (CFSecBuffClusterByUDomNameIdxKey)schema.getFactoryCluster().newByUDomNameIdxKey();
		keyUDomNameIdx.setRequiredFullDomName( Buff.getRequiredFullDomName() );

		CFSecBuffClusterByUDescrIdxKey keyUDescrIdx = (CFSecBuffClusterByUDescrIdxKey)schema.getFactoryCluster().newByUDescrIdxKey();
		keyUDescrIdx.setRequiredDescription( Buff.getRequiredDescription() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUDomNameIdx.containsKey( keyUDomNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"ClusterUDomNameIdx",
				"ClusterUDomNameIdx",
				keyUDomNameIdx );
		}

		if( dictByUDescrIdx.containsKey( keyUDescrIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"ClusterUDescrNameIdx",
				"ClusterUDescrNameIdx",
				keyUDescrIdx );
		}

		// Validate foreign keys

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		dictByUDomNameIdx.put( keyUDomNameIdx, Buff );

		dictByUDescrIdx.put( keyUDescrIdx, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecCluster.CLASS_CODE) {
				CFSecBuffCluster retbuff = ((CFSecBuffCluster)(schema.getFactoryCluster().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	public ICFSecCluster readDerived( ICFSecAuthorization Authorization,
		Long PKey )
	{
		final String S_ProcName = "CFSecRamCluster.readDerived";
		ICFSecCluster buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecCluster lockDerived( ICFSecAuthorization Authorization,
		Long PKey )
	{
		final String S_ProcName = "CFSecRamCluster.lockDerived";
		ICFSecCluster buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecCluster[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamCluster.readAllDerived";
		ICFSecCluster[] retList = new ICFSecCluster[ dictByPKey.values().size() ];
		Iterator< CFSecBuffCluster > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public ICFSecCluster readDerivedByUDomNameIdx( ICFSecAuthorization Authorization,
		String FullDomName )
	{
		final String S_ProcName = "CFSecRamCluster.readDerivedByUDomNameIdx";
		CFSecBuffClusterByUDomNameIdxKey key = (CFSecBuffClusterByUDomNameIdxKey)schema.getFactoryCluster().newByUDomNameIdxKey();

		key.setRequiredFullDomName( FullDomName );
		ICFSecCluster buff;
		if( dictByUDomNameIdx.containsKey( key ) ) {
			buff = dictByUDomNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecCluster readDerivedByUDescrIdx( ICFSecAuthorization Authorization,
		String Description )
	{
		final String S_ProcName = "CFSecRamCluster.readDerivedByUDescrIdx";
		CFSecBuffClusterByUDescrIdxKey key = (CFSecBuffClusterByUDescrIdxKey)schema.getFactoryCluster().newByUDescrIdxKey();

		key.setRequiredDescription( Description );
		ICFSecCluster buff;
		if( dictByUDescrIdx.containsKey( key ) ) {
			buff = dictByUDescrIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecCluster readDerivedByIdIdx( ICFSecAuthorization Authorization,
		long Id )
	{
		final String S_ProcName = "CFSecRamCluster.readDerivedByIdIdx() ";
		ICFSecCluster buff;
		if( dictByPKey.containsKey( Id ) ) {
			buff = dictByPKey.get( Id );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecCluster readRec( ICFSecAuthorization Authorization,
		Long PKey )
	{
		final String S_ProcName = "CFSecRamCluster.readRec";
		ICFSecCluster buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecCluster.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecCluster lockRec( ICFSecAuthorization Authorization,
		Long PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecCluster buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecCluster.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecCluster[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamCluster.readAllRec";
		ICFSecCluster buff;
		ArrayList<ICFSecCluster> filteredList = new ArrayList<ICFSecCluster>();
		ICFSecCluster[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecCluster.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecCluster[0] ) );
	}

	/**
	 *	Read a page of all the specific Cluster buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific Cluster instances in the database accessible for the Authorization.
	 */
	public ICFSecCluster[] pageAllRec( ICFSecAuthorization Authorization,
		Long priorId )
	{
		final String S_ProcName = "pageAllRec";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public ICFSecCluster readRecByIdIdx( ICFSecAuthorization Authorization,
		long Id )
	{
		final String S_ProcName = "CFSecRamCluster.readRecByIdIdx() ";
		ICFSecCluster buff = readDerivedByIdIdx( Authorization,
			Id );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecCluster.CLASS_CODE ) ) {
			return( (ICFSecCluster)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecCluster readRecByUDomNameIdx( ICFSecAuthorization Authorization,
		String FullDomName )
	{
		final String S_ProcName = "CFSecRamCluster.readRecByUDomNameIdx() ";
		ICFSecCluster buff = readDerivedByUDomNameIdx( Authorization,
			FullDomName );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecCluster.CLASS_CODE ) ) {
			return( (ICFSecCluster)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecCluster readRecByUDescrIdx( ICFSecAuthorization Authorization,
		String Description )
	{
		final String S_ProcName = "CFSecRamCluster.readRecByUDescrIdx() ";
		ICFSecCluster buff = readDerivedByUDescrIdx( Authorization,
			Description );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecCluster.CLASS_CODE ) ) {
			return( (ICFSecCluster)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecCluster updateCluster( ICFSecAuthorization Authorization,
		ICFSecCluster iBuff )
	{
		CFSecBuffCluster Buff = (CFSecBuffCluster)ensureRec(iBuff);
		Long pkey = Buff.getPKey();
		CFSecBuffCluster existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateCluster",
				"Existing record not found",
				"Existing record not found",
				"Cluster",
				"Cluster",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateCluster",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffClusterByUDomNameIdxKey existingKeyUDomNameIdx = (CFSecBuffClusterByUDomNameIdxKey)schema.getFactoryCluster().newByUDomNameIdxKey();
		existingKeyUDomNameIdx.setRequiredFullDomName( existing.getRequiredFullDomName() );

		CFSecBuffClusterByUDomNameIdxKey newKeyUDomNameIdx = (CFSecBuffClusterByUDomNameIdxKey)schema.getFactoryCluster().newByUDomNameIdxKey();
		newKeyUDomNameIdx.setRequiredFullDomName( Buff.getRequiredFullDomName() );

		CFSecBuffClusterByUDescrIdxKey existingKeyUDescrIdx = (CFSecBuffClusterByUDescrIdxKey)schema.getFactoryCluster().newByUDescrIdxKey();
		existingKeyUDescrIdx.setRequiredDescription( existing.getRequiredDescription() );

		CFSecBuffClusterByUDescrIdxKey newKeyUDescrIdx = (CFSecBuffClusterByUDescrIdxKey)schema.getFactoryCluster().newByUDescrIdxKey();
		newKeyUDescrIdx.setRequiredDescription( Buff.getRequiredDescription() );

		// Check unique indexes

		if( ! existingKeyUDomNameIdx.equals( newKeyUDomNameIdx ) ) {
			if( dictByUDomNameIdx.containsKey( newKeyUDomNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateCluster",
					"ClusterUDomNameIdx",
					"ClusterUDomNameIdx",
					newKeyUDomNameIdx );
			}
		}

		if( ! existingKeyUDescrIdx.equals( newKeyUDescrIdx ) ) {
			if( dictByUDescrIdx.containsKey( newKeyUDescrIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateCluster",
					"ClusterUDescrNameIdx",
					"ClusterUDescrNameIdx",
					newKeyUDescrIdx );
			}
		}

		// Validate foreign keys

		// Update is valid

		Map< Long, CFSecBuffCluster > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		dictByUDomNameIdx.remove( existingKeyUDomNameIdx );
		dictByUDomNameIdx.put( newKeyUDomNameIdx, Buff );

		dictByUDescrIdx.remove( existingKeyUDescrIdx );
		dictByUDescrIdx.put( newKeyUDescrIdx, Buff );

		return(Buff);
	}

	public void deleteCluster( ICFSecAuthorization Authorization,
		ICFSecCluster iBuff )
	{
		final String S_ProcName = "CFSecRamClusterTable.deleteCluster() ";
		CFSecBuffCluster Buff = (CFSecBuffCluster)ensureRec(iBuff);
		int classCode;
		Long pkey = (Long)(Buff.getPKey());
		CFSecBuffCluster existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteCluster",
				pkey );
		}
		CFSecBuffSecGroup buffDelSecGrpIncByGroup;
		ICFSecSecGroup arrDelSecGrpIncByGroup[] = schema.getTableSecGroup().readDerivedByClusterIdx( Authorization,
			existing.getRequiredId() );
		for( int idxDelSecGrpIncByGroup = 0; idxDelSecGrpIncByGroup < arrDelSecGrpIncByGroup.length; idxDelSecGrpIncByGroup++ ) {
			buffDelSecGrpIncByGroup = (CFSecBuffSecGroup)(arrDelSecGrpIncByGroup[idxDelSecGrpIncByGroup]);
					schema.getTableSecGrpInc().deleteSecGrpIncByIncludeIdx( Authorization,
						buffDelSecGrpIncByGroup.getRequiredSecGroupId() );
		}
		CFSecBuffSecGroup buffDelSecGrpMembs;
		ICFSecSecGroup arrDelSecGrpMembs[] = schema.getTableSecGroup().readDerivedByClusterIdx( Authorization,
			existing.getRequiredId() );
		for( int idxDelSecGrpMembs = 0; idxDelSecGrpMembs < arrDelSecGrpMembs.length; idxDelSecGrpMembs++ ) {
			buffDelSecGrpMembs = (CFSecBuffSecGroup)(arrDelSecGrpMembs[idxDelSecGrpMembs]);
					schema.getTableSecGrpMemb().deleteSecGrpMembByGroupIdx( Authorization,
						buffDelSecGrpMembs.getRequiredSecGroupId() );
		}
		CFSecBuffSecGroup buffDelSecGrpIncs;
		ICFSecSecGroup arrDelSecGrpIncs[] = schema.getTableSecGroup().readDerivedByClusterIdx( Authorization,
			existing.getRequiredId() );
		for( int idxDelSecGrpIncs = 0; idxDelSecGrpIncs < arrDelSecGrpIncs.length; idxDelSecGrpIncs++ ) {
			buffDelSecGrpIncs = (CFSecBuffSecGroup)(arrDelSecGrpIncs[idxDelSecGrpIncs]);
					schema.getTableSecGrpInc().deleteSecGrpIncByGroupIdx( Authorization,
						buffDelSecGrpIncs.getRequiredSecGroupId() );
		}
					schema.getTableSecGroup().deleteSecGroupByClusterIdx( Authorization,
						existing.getRequiredId() );
					schema.getTableTenant().deleteTenantByClusterIdx( Authorization,
						existing.getRequiredId() );
					schema.getTableHostNode().deleteHostNodeByClusterIdx( Authorization,
						existing.getRequiredId() );
		CFSecBuffClusterByUDomNameIdxKey keyUDomNameIdx = (CFSecBuffClusterByUDomNameIdxKey)schema.getFactoryCluster().newByUDomNameIdxKey();
		keyUDomNameIdx.setRequiredFullDomName( existing.getRequiredFullDomName() );

		CFSecBuffClusterByUDescrIdxKey keyUDescrIdx = (CFSecBuffClusterByUDescrIdxKey)schema.getFactoryCluster().newByUDescrIdxKey();
		keyUDescrIdx.setRequiredDescription( existing.getRequiredDescription() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< Long, CFSecBuffCluster > subdict;

		dictByPKey.remove( pkey );

		dictByUDomNameIdx.remove( keyUDomNameIdx );

		dictByUDescrIdx.remove( keyUDescrIdx );

	}
	public void deleteClusterByIdIdx( ICFSecAuthorization Authorization,
		Long argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffCluster cur;
		LinkedList<CFSecBuffCluster> matchSet = new LinkedList<CFSecBuffCluster>();
		Iterator<CFSecBuffCluster> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffCluster> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffCluster)(schema.getTableCluster().readDerivedByIdIdx( Authorization,
				cur.getRequiredId() ));
			deleteCluster( Authorization, cur );
		}
	}

	public void deleteClusterByUDomNameIdx( ICFSecAuthorization Authorization,
		String argFullDomName )
	{
		CFSecBuffClusterByUDomNameIdxKey key = (CFSecBuffClusterByUDomNameIdxKey)schema.getFactoryCluster().newByUDomNameIdxKey();
		key.setRequiredFullDomName( argFullDomName );
		deleteClusterByUDomNameIdx( Authorization, key );
	}

	public void deleteClusterByUDomNameIdx( ICFSecAuthorization Authorization,
		ICFSecClusterByUDomNameIdxKey argKey )
	{
		CFSecBuffCluster cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffCluster> matchSet = new LinkedList<CFSecBuffCluster>();
		Iterator<CFSecBuffCluster> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffCluster> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffCluster)(schema.getTableCluster().readDerivedByIdIdx( Authorization,
				cur.getRequiredId() ));
			deleteCluster( Authorization, cur );
		}
	}

	public void deleteClusterByUDescrIdx( ICFSecAuthorization Authorization,
		String argDescription )
	{
		CFSecBuffClusterByUDescrIdxKey key = (CFSecBuffClusterByUDescrIdxKey)schema.getFactoryCluster().newByUDescrIdxKey();
		key.setRequiredDescription( argDescription );
		deleteClusterByUDescrIdx( Authorization, key );
	}

	public void deleteClusterByUDescrIdx( ICFSecAuthorization Authorization,
		ICFSecClusterByUDescrIdxKey argKey )
	{
		CFSecBuffCluster cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffCluster> matchSet = new LinkedList<CFSecBuffCluster>();
		Iterator<CFSecBuffCluster> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffCluster> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffCluster)(schema.getTableCluster().readDerivedByIdIdx( Authorization,
				cur.getRequiredId() ));
			deleteCluster( Authorization, cur );
		}
	}
}
