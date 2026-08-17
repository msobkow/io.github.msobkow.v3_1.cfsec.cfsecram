
// Description: Java 25 in-memory RAM DbIO implementation for SecTentGrp.

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;

import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.buff.*;
import server.markhome.mcf.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamSecTentGrpTable in-memory RAM DbIO implementation
 *	for SecTentGrp.
 */
public class CFSecRamSecTentGrpTable
	implements ICFSecSecTentGrpTable
{
	private ICFSecSchema schema;
	private Map< ICFLibKeyHash256,
				CFSecBuffSecTentGrp > dictByPKey
		= new HashMap< ICFLibKeyHash256,
				CFSecBuffSecTentGrp >();
	private Map< CFSecBuffSecTentGrpByTenantIdxKey,
				Map< ICFLibKeyHash256,
					CFSecBuffSecTentGrp >> dictByTenantIdx
		= new HashMap< CFSecBuffSecTentGrpByTenantIdxKey,
				Map< ICFLibKeyHash256,
					CFSecBuffSecTentGrp >>();
	private Map< CFSecBuffSecTentGrpByNameIdxKey,
				Map< ICFLibKeyHash256,
					CFSecBuffSecTentGrp >> dictByNameIdx
		= new HashMap< CFSecBuffSecTentGrpByNameIdxKey,
				Map< ICFLibKeyHash256,
					CFSecBuffSecTentGrp >>();
	private Map< CFSecBuffSecTentGrpByUNameIdxKey,
			CFSecBuffSecTentGrp > dictByUNameIdx
		= new HashMap< CFSecBuffSecTentGrpByUNameIdxKey,
			CFSecBuffSecTentGrp >();

	public CFSecRamSecTentGrpTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecTentGrp ensureRec(ICFSecSecTentGrp rec) {
		return (((CFSecBuffSecTentGrpFactoryService)(schema.getCFSecBuffFactory().getFactorySecTentGrp())).ensureRec(rec));
	}

	@Override
	public ICFSecSecTentGrp createSecTentGrp( ICFSecAuthorization Authorization,
		ICFSecSecTentGrp iBuff )
	{
		final String S_ProcName = "createSecTentGrp";
		
		CFSecBuffSecTentGrp Buff = (CFSecBuffSecTentGrp)ensureRec(iBuff);
		ICFLibKeyHash256 pkey;
		pkey = schema.nextSecTentGrpIdGen();
		Buff.setRequiredSecTentGrpId( pkey );
		CFSecBuffSecTentGrpByTenantIdxKey keyTenantIdx = (CFSecBuffSecTentGrpByTenantIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrp().newByTenantIdxKey();
		keyTenantIdx.setRequiredTenantId( Buff.getRequiredTenantId() );

		CFSecBuffSecTentGrpByNameIdxKey keyNameIdx = (CFSecBuffSecTentGrpByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrp().newByNameIdxKey();
		keyNameIdx.setRequiredName( Buff.getRequiredName() );

		CFSecBuffSecTentGrpByUNameIdxKey keyUNameIdx = (CFSecBuffSecTentGrpByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrp().newByUNameIdxKey();
		keyUNameIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		keyUNameIdx.setRequiredName( Buff.getRequiredName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUNameIdx.containsKey( keyUNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecTentGrpUNameIdx",
				"SecTentGrpUNameIdx",
				keyUNameIdx );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableTenant().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTenantId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Owner",
						"Owner",
						"SecTentGrpTenant",
						"SecTentGrpTenant",
						"Tenant",
						"Tenant",
						null );
				}
			}
		}

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableSecSysGrp().readDerivedByUNameIdx( Authorization,
						Buff.getRequiredName() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"Container",
						"SecTentGrpRefSysGrp",
						"SecTentGrpRefSysGrp",
						"SecSysGrp",
						"SecSysGrp",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< ICFLibKeyHash256, CFSecBuffSecTentGrp > subdictTenantIdx;
		if( dictByTenantIdx.containsKey( keyTenantIdx ) ) {
			subdictTenantIdx = dictByTenantIdx.get( keyTenantIdx );
		}
		else {
			subdictTenantIdx = new HashMap< ICFLibKeyHash256, CFSecBuffSecTentGrp >();
			dictByTenantIdx.put( keyTenantIdx, subdictTenantIdx );
		}
		subdictTenantIdx.put( pkey, Buff );

		Map< ICFLibKeyHash256, CFSecBuffSecTentGrp > subdictNameIdx;
		if( dictByNameIdx.containsKey( keyNameIdx ) ) {
			subdictNameIdx = dictByNameIdx.get( keyNameIdx );
		}
		else {
			subdictNameIdx = new HashMap< ICFLibKeyHash256, CFSecBuffSecTentGrp >();
			dictByNameIdx.put( keyNameIdx, subdictNameIdx );
		}
		subdictNameIdx.put( pkey, Buff );

		dictByUNameIdx.put( keyUNameIdx, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecTentGrp.CLASS_CODE) {
				CFSecBuffSecTentGrp retbuff = ((CFSecBuffSecTentGrp)(schema.getCFSecBuffFactory().getFactorySecTentGrp().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecTentGrp readDerived( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecTentGrp.readDerived";
		ICFSecSecTentGrp buff;
		if( PKey == null ) {
			return( null );
		}
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentGrp lockDerived( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecTentGrp.lockDerived";
		ICFSecSecTentGrp buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentGrp[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecTentGrp.readAllDerived";
		ICFSecSecTentGrp[] retList = new ICFSecSecTentGrp[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecTentGrp > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecSecTentGrp[] readDerivedByTenantIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 TenantId )
	{
		final String S_ProcName = "CFSecRamSecTentGrp.readDerivedByTenantIdx";
		CFSecBuffSecTentGrpByTenantIdxKey key = (CFSecBuffSecTentGrpByTenantIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrp().newByTenantIdxKey();

		key.setRequiredTenantId( TenantId );
		ICFSecSecTentGrp[] recArray;
		if( dictByTenantIdx.containsKey( key ) ) {
			Map< ICFLibKeyHash256, CFSecBuffSecTentGrp > subdictTenantIdx
				= dictByTenantIdx.get( key );
			recArray = new ICFSecSecTentGrp[ subdictTenantIdx.size() ];
			Iterator< CFSecBuffSecTentGrp > iter = subdictTenantIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< ICFLibKeyHash256, CFSecBuffSecTentGrp > subdictTenantIdx
				= new HashMap< ICFLibKeyHash256, CFSecBuffSecTentGrp >();
			dictByTenantIdx.put( key, subdictTenantIdx );
			recArray = new ICFSecSecTentGrp[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecTentGrp[] readDerivedByNameIdx( ICFSecAuthorization Authorization,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecTentGrp.readDerivedByNameIdx";
		CFSecBuffSecTentGrpByNameIdxKey key = (CFSecBuffSecTentGrpByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrp().newByNameIdxKey();

		key.setRequiredName( Name );
		ICFSecSecTentGrp[] recArray;
		if( dictByNameIdx.containsKey( key ) ) {
			Map< ICFLibKeyHash256, CFSecBuffSecTentGrp > subdictNameIdx
				= dictByNameIdx.get( key );
			recArray = new ICFSecSecTentGrp[ subdictNameIdx.size() ];
			Iterator< CFSecBuffSecTentGrp > iter = subdictNameIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< ICFLibKeyHash256, CFSecBuffSecTentGrp > subdictNameIdx
				= new HashMap< ICFLibKeyHash256, CFSecBuffSecTentGrp >();
			dictByNameIdx.put( key, subdictNameIdx );
			recArray = new ICFSecSecTentGrp[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecTentGrp readDerivedByUNameIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 TenantId,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecTentGrp.readDerivedByUNameIdx";
		CFSecBuffSecTentGrpByUNameIdxKey key = (CFSecBuffSecTentGrpByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrp().newByUNameIdxKey();

		key.setRequiredTenantId( TenantId );
		key.setRequiredName( Name );
		ICFSecSecTentGrp buff;
		if( dictByUNameIdx.containsKey( key ) ) {
			buff = dictByUNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentGrp readDerivedByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecTentGrpId )
	{
		final String S_ProcName = "CFSecRamSecTentGrp.readDerivedByIdIdx() ";
		ICFSecSecTentGrp buff;
		if( dictByPKey.containsKey( SecTentGrpId ) ) {
			buff = dictByPKey.get( SecTentGrpId );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentGrp readRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecTentGrp.readRec";
		ICFSecSecTentGrp buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecTentGrp.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentGrp lockRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecTentGrp buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecTentGrp.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentGrp[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecTentGrp.readAllRec";
		ICFSecSecTentGrp buff;
		ArrayList<ICFSecSecTentGrp> filteredList = new ArrayList<ICFSecSecTentGrp>();
		ICFSecSecTentGrp[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecTentGrp.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecTentGrp[0] ) );
	}

	@Override
	public ICFSecSecTentGrp readRecByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecTentGrpId )
	{
		final String S_ProcName = "CFSecRamSecTentGrp.readRecByIdIdx() ";
		ICFSecSecTentGrp buff = readDerivedByIdIdx( Authorization,
			SecTentGrpId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecTentGrp.CLASS_CODE ) ) {
			return( (ICFSecSecTentGrp)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecTentGrp[] readRecByTenantIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 TenantId )
	{
		final String S_ProcName = "CFSecRamSecTentGrp.readRecByTenantIdx() ";
		ICFSecSecTentGrp buff;
		ArrayList<ICFSecSecTentGrp> filteredList = new ArrayList<ICFSecSecTentGrp>();
		ICFSecSecTentGrp[] buffList = readDerivedByTenantIdx( Authorization,
			TenantId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecTentGrp.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecTentGrp)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecTentGrp[0] ) );
	}

	@Override
	public ICFSecSecTentGrp[] readRecByNameIdx( ICFSecAuthorization Authorization,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecTentGrp.readRecByNameIdx() ";
		ICFSecSecTentGrp buff;
		ArrayList<ICFSecSecTentGrp> filteredList = new ArrayList<ICFSecSecTentGrp>();
		ICFSecSecTentGrp[] buffList = readDerivedByNameIdx( Authorization,
			Name );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecTentGrp.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecTentGrp)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecTentGrp[0] ) );
	}

	@Override
	public ICFSecSecTentGrp readRecByUNameIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 TenantId,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecTentGrp.readRecByUNameIdx() ";
		ICFSecSecTentGrp buff = readDerivedByUNameIdx( Authorization,
			TenantId,
			Name );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecTentGrp.CLASS_CODE ) ) {
			return( (ICFSecSecTentGrp)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecSecTentGrp updateSecTentGrp( ICFSecAuthorization Authorization,
		ICFSecSecTentGrp iBuff )
	{
		CFSecBuffSecTentGrp Buff = (CFSecBuffSecTentGrp)ensureRec(iBuff);
		ICFLibKeyHash256 pkey = (ICFLibKeyHash256)Buff.getPKey();
		CFSecBuffSecTentGrp existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecTentGrp",
				"Existing record not found",
				"Existing record not found",
				"SecTentGrp",
				"SecTentGrp",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecTentGrp",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecTentGrpByTenantIdxKey existingKeyTenantIdx = (CFSecBuffSecTentGrpByTenantIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrp().newByTenantIdxKey();
		existingKeyTenantIdx.setRequiredTenantId( existing.getRequiredTenantId() );

		CFSecBuffSecTentGrpByTenantIdxKey newKeyTenantIdx = (CFSecBuffSecTentGrpByTenantIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrp().newByTenantIdxKey();
		newKeyTenantIdx.setRequiredTenantId( Buff.getRequiredTenantId() );

		CFSecBuffSecTentGrpByNameIdxKey existingKeyNameIdx = (CFSecBuffSecTentGrpByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrp().newByNameIdxKey();
		existingKeyNameIdx.setRequiredName( existing.getRequiredName() );

		CFSecBuffSecTentGrpByNameIdxKey newKeyNameIdx = (CFSecBuffSecTentGrpByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrp().newByNameIdxKey();
		newKeyNameIdx.setRequiredName( Buff.getRequiredName() );

		CFSecBuffSecTentGrpByUNameIdxKey existingKeyUNameIdx = (CFSecBuffSecTentGrpByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrp().newByUNameIdxKey();
		existingKeyUNameIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		existingKeyUNameIdx.setRequiredName( existing.getRequiredName() );

		CFSecBuffSecTentGrpByUNameIdxKey newKeyUNameIdx = (CFSecBuffSecTentGrpByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrp().newByUNameIdxKey();
		newKeyUNameIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		newKeyUNameIdx.setRequiredName( Buff.getRequiredName() );

		// Check unique indexes

		if( ! existingKeyUNameIdx.equals( newKeyUNameIdx ) ) {
			if( dictByUNameIdx.containsKey( newKeyUNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecTentGrp",
					"SecTentGrpUNameIdx",
					"SecTentGrpUNameIdx",
					newKeyUNameIdx );
			}
		}

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableTenant().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTenantId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSecTentGrp",
						"Owner",
						"Owner",
						"SecTentGrpTenant",
						"SecTentGrpTenant",
						"Tenant",
						"Tenant",
						null );
				}
			}
		}

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableSecSysGrp().readDerivedByUNameIdx( Authorization,
						Buff.getRequiredName() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSecTentGrp",
						"Container",
						"Container",
						"SecTentGrpRefSysGrp",
						"SecTentGrpRefSysGrp",
						"SecSysGrp",
						"SecSysGrp",
						null );
				}
			}
		}

		// Update is valid

		Map< ICFLibKeyHash256, CFSecBuffSecTentGrp > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictByTenantIdx.get( existingKeyTenantIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByTenantIdx.containsKey( newKeyTenantIdx ) ) {
			subdict = dictByTenantIdx.get( newKeyTenantIdx );
		}
		else {
			subdict = new HashMap< ICFLibKeyHash256, CFSecBuffSecTentGrp >();
			dictByTenantIdx.put( newKeyTenantIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByNameIdx.get( existingKeyNameIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByNameIdx.containsKey( newKeyNameIdx ) ) {
			subdict = dictByNameIdx.get( newKeyNameIdx );
		}
		else {
			subdict = new HashMap< ICFLibKeyHash256, CFSecBuffSecTentGrp >();
			dictByNameIdx.put( newKeyNameIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByUNameIdx.remove( existingKeyUNameIdx );
		dictByUNameIdx.put( newKeyUNameIdx, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecTentGrp( ICFSecAuthorization Authorization,
		ICFSecSecTentGrp iBuff )
	{
		final String S_ProcName = "CFSecRamSecTentGrpTable.deleteSecTentGrp() ";
		CFSecBuffSecTentGrp Buff = (CFSecBuffSecTentGrp)ensureRec(iBuff);
		int classCode;
		ICFLibKeyHash256 pkey = (ICFLibKeyHash256)(Buff.getPKey());
		CFSecBuffSecTentGrp existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecTentGrp",
				pkey );
		}
					schema.getTableSecTentGrpMemb().deleteSecTentGrpMembByTentGrpIdx( Authorization,
						existing.getRequiredSecTentGrpId() );
		CFSecBuffSecTentGrpByTenantIdxKey keyTenantIdx = (CFSecBuffSecTentGrpByTenantIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrp().newByTenantIdxKey();
		keyTenantIdx.setRequiredTenantId( existing.getRequiredTenantId() );

		CFSecBuffSecTentGrpByNameIdxKey keyNameIdx = (CFSecBuffSecTentGrpByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrp().newByNameIdxKey();
		keyNameIdx.setRequiredName( existing.getRequiredName() );

		CFSecBuffSecTentGrpByUNameIdxKey keyUNameIdx = (CFSecBuffSecTentGrpByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrp().newByUNameIdxKey();
		keyUNameIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		keyUNameIdx.setRequiredName( existing.getRequiredName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< ICFLibKeyHash256, CFSecBuffSecTentGrp > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByTenantIdx.get( keyTenantIdx );
		subdict.remove( pkey );

		subdict = dictByNameIdx.get( keyNameIdx );
		subdict.remove( pkey );

		dictByUNameIdx.remove( keyUNameIdx );

	}
	@Override
	public void deleteSecTentGrpByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecTentGrp cur;
		LinkedList<CFSecBuffSecTentGrp> matchSet = new LinkedList<CFSecBuffSecTentGrp>();
		Iterator<CFSecBuffSecTentGrp> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecTentGrp> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecTentGrp)(schema.getTableSecTentGrp().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecTentGrpId() ));
			deleteSecTentGrp( Authorization, cur );
		}
	}

	@Override
	public void deleteSecTentGrpByTenantIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argTenantId )
	{
		CFSecBuffSecTentGrpByTenantIdxKey key = (CFSecBuffSecTentGrpByTenantIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrp().newByTenantIdxKey();
		key.setRequiredTenantId( argTenantId );
		deleteSecTentGrpByTenantIdx( Authorization, key );
	}

	@Override
	public void deleteSecTentGrpByTenantIdx( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpByTenantIdxKey argKey )
	{
		CFSecBuffSecTentGrp cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecTentGrp> matchSet = new LinkedList<CFSecBuffSecTentGrp>();
		Iterator<CFSecBuffSecTentGrp> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecTentGrp> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecTentGrp)(schema.getTableSecTentGrp().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecTentGrpId() ));
			deleteSecTentGrp( Authorization, cur );
		}
	}

	@Override
	public void deleteSecTentGrpByNameIdx( ICFSecAuthorization Authorization,
		String argName )
	{
		CFSecBuffSecTentGrpByNameIdxKey key = (CFSecBuffSecTentGrpByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrp().newByNameIdxKey();
		key.setRequiredName( argName );
		deleteSecTentGrpByNameIdx( Authorization, key );
	}

	@Override
	public void deleteSecTentGrpByNameIdx( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpByNameIdxKey argKey )
	{
		CFSecBuffSecTentGrp cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecTentGrp> matchSet = new LinkedList<CFSecBuffSecTentGrp>();
		Iterator<CFSecBuffSecTentGrp> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecTentGrp> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecTentGrp)(schema.getTableSecTentGrp().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecTentGrpId() ));
			deleteSecTentGrp( Authorization, cur );
		}
	}

	@Override
	public void deleteSecTentGrpByUNameIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argTenantId,
		String argName )
	{
		CFSecBuffSecTentGrpByUNameIdxKey key = (CFSecBuffSecTentGrpByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrp().newByUNameIdxKey();
		key.setRequiredTenantId( argTenantId );
		key.setRequiredName( argName );
		deleteSecTentGrpByUNameIdx( Authorization, key );
	}

	@Override
	public void deleteSecTentGrpByUNameIdx( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpByUNameIdxKey argKey )
	{
		CFSecBuffSecTentGrp cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecTentGrp> matchSet = new LinkedList<CFSecBuffSecTentGrp>();
		Iterator<CFSecBuffSecTentGrp> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecTentGrp> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecTentGrp)(schema.getTableSecTentGrp().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecTentGrpId() ));
			deleteSecTentGrp( Authorization, cur );
		}
	}
}
